"""
Centralized file extension definitions for static scanners.

This module contains all file extension constants used across different scanners
to avoid duplication and ensure consistency.
"""

from enum import Enum

# Pickle and serialized object formats
PICKLE_EXTENSIONS = {
    # Standard pickle formats
    '.pkl', '.pickle', '.p', '.joblib', '.dat', '.data',
    # PyTorch (uses pickle internally)
    '.pt', '.pth',
    # NumPy (uses pickle for object arrays)
    '.npy', '.npz'
}

# Machine Learning model formats
ML_MODEL_EXTENSIONS = {
    # PyTorch (checkpoint formats)
    '.bin', '.ckpt',
    # TensorFlow/Keras
    '.h5', '.hdf5', '.pb', '.keras',
    # ONNX
    '.onnx',
    # SafeTensors
    '.safetensors',
    # TensorFlow Lite
    '.tflite',
    # Core ML
    '.mlmodel',
    # Other
    '.model', '.weights'
}

# Combined sets for convenience
SERIALIZED_EXTENSIONS = PICKLE_EXTENSIONS | ML_MODEL_EXTENSIONS
SCANNABLE_EXTENSIONS = SERIALIZED_EXTENSIONS  # Alias for backward compatibility


class FileType(Enum):
    """Enumeration of file types for scanning classification."""
    ZIP = 'zip'
    TAR = 'tar'
    SERIALIZED = 'serialized'
    OTHER = 'other'


def is_pickle_file(filepath: str) -> bool:
    """Check if a file is a pickle format."""
    return any(filepath.lower().endswith(ext) for ext in PICKLE_EXTENSIONS)

def is_ml_model_file(filepath: str) -> bool:
    """Check if a file is a machine learning model."""
    return any(filepath.lower().endswith(ext) for ext in ML_MODEL_EXTENSIONS)

def is_serialized_file(filepath: str) -> bool:
    """Check if a file contains serialized data (pickle or ML model)."""
    return any(filepath.lower().endswith(ext) for ext in SERIALIZED_EXTENSIONS)

def should_scan_file(filepath: str) -> bool:
    """Check if a file should be scanned by security scanners."""
    return is_serialized_file(filepath)