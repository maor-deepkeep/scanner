import boto3
import hashlib
import json
import logging

from typing import Dict, Any, Optional
from botocore.exceptions import ClientError
from botocore.config import Config

logger = logging.getLogger(__name__)

class MinIOClient:
    def __init__(self, url: str, access_key: str, secret_key: str, region: str = "us-east-1"):
        """
        Initialize MinIO client using S3-compatible API
        
        Args:
            url: MinIO server URL (e.g., "http://localhost:9000")
            access_key: MinIO access key (default: minioadmin)
            secret_key: MinIO secret key (default: minioadmin)
            region: AWS region for S3 compatibility (default: us-east-1)
        """
        self.url = url.rstrip("/")
        self.access_key = access_key
        self.secret_key = secret_key
        
        # Configure boto3 for MinIO
        self.s3_client = boto3.client(
            's3',
            endpoint_url=self.url,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region,
            config=Config(signature_version='s3v4')
        )

    def _calculate_digest(self, file_path: str) -> str:
        """Calculate SHA256 digest of a file"""
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                h.update(chunk)
        return "sha256:" + h.hexdigest()

    def manifest_exists(self, bucket: str, model_name: str, model_version: str) -> bool:
        """
        Check if a model manifest exists in MinIO
        Uses bucket/key structure: repo/tag.manifest.json
        """
        key = f"{model_name}/{model_version}.manifest.json"
        
        try:
            self.s3_client.head_object(Bucket=bucket, Key=key)
            return True
        except ClientError as e:
            if e.response['Error']['Code'] == '404':
                return False
            raise

    def _ensure_bucket_exists(self, bucket: str) -> Dict[str, Any]:
        """
        Ensure the bucket exists in MinIO. If not, create it.
        
        Args:
            bucket: Bucket name
            
        Returns:
            Dict with bucket status
        """
        try:
            # Check if bucket exists
            self.s3_client.head_bucket(Bucket=bucket)
            return {"bucket": bucket, "status": "exists"}
        except ClientError as e:
            if e.response['Error']['Code'] == '404':
                # Create bucket
                try:
                    # Always create buckets with object lock enabled for immutability
                    self.s3_client.create_bucket(
                        Bucket=bucket,
                        ObjectLockEnabledForBucket=True
                    )
                    return {"bucket": bucket, "status": "created"}
                except ClientError as create_error:
                    raise Exception(f"Failed to create bucket {bucket}: {create_error}")
            else:
                raise

    def get_manifest(self, bucket: str, model_name: str, model_version: str, output_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Download a manifest from MinIO
        
        Args:
            bucket: Bucket name (bucket)
            model_name: Model name
            model_version: Model version
            output_path: Optional local path to save the file
            
        Returns:
            Dict with download information and data
        """
        key = f"{model_name}/{model_version}.manifest.json"
        
        try:
            # Get object metadata
            response = self.s3_client.head_object(Bucket=bucket, Key=key)
            metadata = response.get('Metadata', {})
            
            # Download object
            obj_response = self.s3_client.get_object(Bucket=bucket, Key=key)
            data = obj_response['Body'].read()
            
            # Save to file if output_path provided
            if output_path:
                with open(output_path, 'wb') as f:
                    f.write(data)
            
            return {
                "model": model_name,
                "version": model_version,
                "data": data,
                "digest": metadata.get('digest'),
                "bucket": bucket,
                "key": key,
                "size": len(data),
                "last_modified": response['LastModified']
            }
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchKey':
                raise Exception(f"Model manifest {model_name}:{model_version} not found in bucket {bucket}")
            raise Exception(f"Failed to download model manifest {model_name}:{model_version}: {e}")

    def upload_manifest(self, bucket: str, model_name: str, model_version: str, manifest_data: dict) -> Dict[str, Any]:
        """
        Upload a manifest (metadata) for a model to MinIO
        
        Args:
            bucket: Project name (bucket)
            model_name: Model name
            model_version: Model version
            manifest_data: Manifest data as dictionary
            
        Returns:
            Dict with upload information
        """
        key = f"{model_name}/{model_version}.manifest.json"
        
        try:
            # Ensure bucket exists
            self._ensure_bucket_exists(bucket)
            
            # Convert manifest to JSON and upload
            manifest_json = json.dumps(manifest_data, indent=2)
            
            self.s3_client.put_object(
                Bucket=bucket,
                Key=key,
                Body=manifest_json.encode(),
                ContentType='application/json',
                Metadata={
                    'model-name': model_name,
                    'version': model_version,
                    'type': 'manifest'
                }
            )
            
            # Always set legal hold for immutability (internal)
            self._set_legal_hold(bucket, key)
            
            return {
                "model": model_name,
                "version": model_version,
                "bucket": bucket,
                "key": key,
                "type": "manifest"
            }
            
        except Exception as e:
            raise Exception(f"Failed to upload manifest for {model_name}:{model_version}: {e}")

    def _set_legal_hold(self, bucket: str, key: str) -> None:
        """
        Internal method to set legal hold on an object for immutability.
        Always enables legal hold - this is not configurable.
        
        Args:
            bucket: Bucket name
            key: Object key
        """
        try:
            self.s3_client.put_object_legal_hold(
                Bucket=bucket,
                Key=key,
                LegalHold={'Status': 'ON'}
            )
        except ClientError as e:
            # Log warning but don't fail - object lock might not be enabled
            logger.warning(f"Could not set legal hold on {bucket}/{key}: {e}")





