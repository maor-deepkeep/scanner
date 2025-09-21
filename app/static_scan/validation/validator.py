import os
import hashlib
import json
import logging
import datetime

from clients.minio_client import MinIOClient
from models import ModelArtifact, ModelFile, Manifest, ValidationResult, Verdict

logger = logging.getLogger(__name__)

class Validator:

    def __init__(self, org_id: str):
        self._minio_client = MinIOClient(
            url=os.getenv("MINIO_URL"),
            access_key=os.getenv("MINIO_ACCESS_KEY"),
            secret_key=os.getenv("MINIO_SECRET_KEY")
        )
        self._minio_project = f"model-total-{org_id}"

    def _calculate_hash_for_path(self, path: str) -> str:
        """
        Compute SHA256 hash of a file's content.
        """
        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    
    def _calculate_hash_for_manifest(self, model_files: list[ModelFile]) -> str:
        """
        Compute a stable hash from a list of (hash, path) pairs,
        independent of the order of the list.
        """
        sha256 = hashlib.sha256()

        # Normalize into "hash path" strings
        normalized = [f"{model_file.path} {model_file.hash}" for model_file in model_files]

        # Sort to make order irrelevant
        for item in sorted(normalized):
            sha256.update(item.encode("utf-8"))

        return sha256.hexdigest()

    def _create_model_file(self, root_dir: str, path: str) -> ModelFile:
        full_path = os.path.join(root_dir, path)
        file_content_hash = self._calculate_hash_for_path(full_path)
        return ModelFile(path=path, hash=file_content_hash)
    
    def _create_manifest(self, model_files: list[ModelFile]) -> Manifest:
        manifest_hash = self._calculate_hash_for_manifest(model_files)
        return Manifest(files=model_files, manifest_hash=manifest_hash)

    def _list_files_recursive(self, root_dir: str) -> list[str]:
        """
        Recursively collects all relative file paths under `root_dir`.
        """
        file_paths = []
        for dirpath, _, filenames in os.walk(root_dir):
            for filename in filenames:
                full_path = os.path.join(dirpath, filename)
                relative_path = os.path.relpath(full_path, root_dir)
                file_paths.append(relative_path)
        return file_paths
    
    def _load_manifest_from_bytes(self, data: bytes) -> Manifest:
        manifest_dict = json.loads(data.decode())
        return Manifest(**manifest_dict)
    
    def _get_verdict(self, old_manifest: Manifest, new_manifest: Manifest) -> tuple[Verdict, list[str]]:

        # Check manifest hash first
        if old_manifest.manifest_hash == new_manifest.manifest_hash:
            return Verdict.VALID, []

        # Create dictionaries for efficient lookup by path
        old_files = {f.path: f.hash for f in old_manifest.files}
        new_files = {f.path: f.hash for f in new_manifest.files}
        
        changed_files = []
        
        # Check for modified or added files
        for path, new_hash in new_files.items():
            if path not in old_files or old_files[path] != new_hash:
                changed_files.append(path)
        
        # Check for removed files
        for path in old_files:
            if path not in new_files:
                changed_files.append(path)
        
        if changed_files:
            return Verdict.TAMPERED, changed_files
        
        return Verdict.VALID, []
        
    def validate(self, model_artifact: ModelArtifact) -> ValidationResult:
        logger.info("Validating")
        validation_time = datetime.datetime.now()
        all_files = self._list_files_recursive(model_artifact.folder_path)

        model_files = []
        for file_path in all_files:
            model_file = self._create_model_file(model_artifact.folder_path, file_path)
            model_files.append(model_file)

        manifest = self._create_manifest(model_files)

        logger.info(f"Created manifest: {manifest}")

        artifact_exists = self._minio_client.manifest_exists(self._minio_project, model_artifact.metadata.model_name, model_artifact.metadata.model_version)
        if not artifact_exists:
            logger.info("Artifact doesn't exists, returning VALID and uploading to remote")
            self._minio_client.upload_manifest(self._minio_project, model_artifact.metadata.model_name, model_artifact.metadata.model_version, manifest.model_dump(mode='json'))
            NO_OLD_ARTIFACT = None
            return ValidationResult(old_manifest=NO_OLD_ARTIFACT, new_manifest=manifest, verdict=Verdict.VALID, changed_files=[], validated_at=validation_time)
        
        logger.info("Artifact exists, comparing with remote manifest")
        result = self._minio_client.get_manifest(self._minio_project, model_artifact.metadata.model_name, model_artifact.metadata.model_version)
        remote_manifest = self._load_manifest_from_bytes(result["data"])

        verdict, changed_files = self._get_verdict(manifest, remote_manifest)
        logger.info(f"Verdict after comparing: {verdict}, changed files: {changed_files}")
        return ValidationResult(old_manifest=remote_manifest, new_manifest=manifest, verdict=verdict, changed_files=changed_files, validated_at=validation_time)


        