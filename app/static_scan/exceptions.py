"""
Custom exceptions for static scan components.

This module defines custom exception classes for different scanners and components
in the static scan system. Using specific exceptions helps with error handling,
debugging, and maintaining clear error boundaries between components.
"""

from typing import Optional, Any


class StaticScanError(Exception):
    """Base exception class for all static scan related errors."""
    
    def __init__(self, message: str, original_error: Optional[Exception] = None):
        """
        Initialize the static scan error.
        
        Args:
            message: Error message describing what went wrong
            original_error: The original exception that caused this error
        """
        super().__init__(message)
        self.original_error = original_error
        
    def __str__(self) -> str:
        """Return string representation of the error."""
        if self.original_error:
            return f"{super().__str__()} (caused by: {self.original_error})"
        return super().__str__()


class ScannerError(StaticScanError):
    """Base exception class for scanner-specific errors."""
    
    def __init__(self, scanner_name: str, message: str, original_error: Optional[Exception] = None):
        """
        Initialize the scanner error.
        
        Args:
            scanner_name: Name of the scanner that raised the error
            message: Error message describing what went wrong
            original_error: The original exception that caused this error
        """
        self.scanner_name = scanner_name
        super().__init__(f"[{scanner_name}] {message}", original_error)


class ModelScanError(ScannerError):
    """Exception raised by ModelScan scanner operations."""
    
    def __init__(self, message: str, original_error: Optional[Exception] = None):
        """Initialize ModelScan error."""
        super().__init__("ModelScan", message, original_error)


class PickleScanError(ScannerError):
    """Exception raised by PickleScan scanner operations."""
    
    def __init__(self, message: str, original_error: Optional[Exception] = None):
        """Initialize PickleScan error."""
        super().__init__("PickleScan", message, original_error)


class FicklingScanError(ScannerError):
    """Exception raised by Fickling scanner operations."""
    
    def __init__(self, message: str, original_error: Optional[Exception] = None):
        """Initialize Fickling error."""
        super().__init__("Fickling", message, original_error)


class ModelAuditError(ScannerError):
    """Exception raised by ModelAudit scanner operations."""
    
    def __init__(self, message: str, original_error: Optional[Exception] = None):
        """Initialize ModelAudit error."""
        super().__init__("ModelAudit", message, original_error)


class ScannerNotAvailableError(StaticScanError):
    """Exception raised when a scanner is not available or cannot be imported."""
    
    def __init__(self, scanner_name: str, reason: str, original_error: Optional[Exception] = None):
        """
        Initialize scanner not available error.
        
        Args:
            scanner_name: Name of the unavailable scanner
            reason: Reason why the scanner is not available
            original_error: The original import or initialization error
        """
        self.scanner_name = scanner_name
        self.reason = reason
        message = f"Scanner '{scanner_name}' is not available: {reason}"
        super().__init__(message, original_error)


class ScanTimeoutError(StaticScanError):
    """Exception raised when a scan operation times out."""
    
    def __init__(self, scanner_name: str, timeout_seconds: int):
        """
        Initialize scan timeout error.
        
        Args:
            scanner_name: Name of the scanner that timed out
            timeout_seconds: The timeout duration in seconds
        """
        self.scanner_name = scanner_name
        self.timeout_seconds = timeout_seconds
        message = f"Scanner '{scanner_name}' timed out after {timeout_seconds} seconds"
        super().__init__(message)


class ValidationError(StaticScanError):
    """Exception raised when input validation fails."""
    
    def __init__(self, field: str, value: Any, reason: str):
        """
        Initialize validation error.
        
        Args:
            field: The field that failed validation
            value: The invalid value
            reason: Reason why validation failed
        """
        self.field = field
        self.value = value
        self.reason = reason
        message = f"Validation failed for field '{field}' with value '{value}': {reason}"
        super().__init__(message)