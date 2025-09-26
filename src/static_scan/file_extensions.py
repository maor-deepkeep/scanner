"""
Centralized file extension definitions for static scanners.

This module contains all file extension constants used across different scanners
to avoid duplication and ensure consistency.
"""

# Pickle and serialized object formats
PICKLE_EXTENSIONS = {
    '.pkl', '.pickle', '.p', '.joblib', '.dat', '.data'
}

# Machine Learning model formats
ML_MODEL_EXTENSIONS = {
    # PyTorch
    '.pt', '.pth', '.bin', '.ckpt',
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