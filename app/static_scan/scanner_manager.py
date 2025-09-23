"""
Scanner Manager - Handles scanner availability and registration
"""
import importlib
import importlib.util
import logging
import traceback
from typing import Dict, Optional, Any, ClassVar
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class ScannerInfo:
    """Information about a scanner"""
    name: str
    module_path: str
    class_name: str
    is_available: bool
    instance: Optional[Any] = None
    error: Optional[str] = None


class ScannerManager:
    """Manages available scanners and their status"""
    
    # Base module path for all scanners - handles both package and direct imports
    BASE_SCANNERS_MODULE = f"{__package__}.scanners" if __package__ else "app.static_scan.scanners"
    
    # Define all scanners and their import paths
    SCANNER_DEFINITIONS: ClassVar[dict] = {
        'modelscan': {
            'module_path': f'{BASE_SCANNERS_MODULE}.modelscan_scanner',
            'class_name': 'ModelScanScanner',
            'required_packages': ['modelscan']
        },
        'picklescan': {
            'module_path': f'{BASE_SCANNERS_MODULE}.picklescan_scanner',
            'class_name': 'PickleScanScanner',
            'required_packages': ['picklescan']
        },
        'fickling': {
            'module_path': f'{BASE_SCANNERS_MODULE}.fickling_scanner',
            'class_name': 'FicklingScanner',
            'required_packages': ['fickling']
        },
        'modelaudit': {
            'module_path': f'{BASE_SCANNERS_MODULE}.modelaudit_scanner',
            'class_name': 'ModelAuditScanner',
            'required_packages': ['modelaudit']
        }
    }
    
    def __init__(self):
        self.scanners: Dict[str, ScannerInfo] = {}
        self._initialize_scanners()
    
    def _check_package_available(self, package_name: str) -> bool:
        """Check if a package is available for import"""
        spec = importlib.util.find_spec(package_name)
        return spec is not None
    
    def _initialize_scanners(self):
        """Initialize all scanners and check their availability"""
        for scanner_name, config in self.SCANNER_DEFINITIONS.items():
            scanner_info = ScannerInfo(
                name=scanner_name,
                module_path=config['module_path'],
                class_name=config['class_name'],
                is_available=False
            )
            
            # Check if required packages are available
            packages_available = all(
                self._check_package_available(pkg) 
                for pkg in config.get('required_packages', [])
            )
            
            if not packages_available:
                scanner_info.error = f"Required packages not available: {config.get('required_packages')}"
                logger.warning(f"Scanner {scanner_name} not available: {scanner_info.error}")
            else:
                try:
                    # Try to import the scanner module
                    module = importlib.import_module(config['module_path'])
                    scanner_class = getattr(module, config['class_name'])
                    scanner_info.instance = scanner_class()
                    scanner_info.is_available = True
                    logger.info(f"Scanner {scanner_name} initialized successfully")
                except (ImportError, AttributeError) as e:
                    scanner_info.error = f"{type(e).__name__}: {str(e)}"
                    logger.warning(f"Failed to initialize scanner {scanner_name}: {scanner_info.error}")
                    logger.debug(f"Stack trace for {scanner_name}:\n{traceback.format_exc()}")
                except Exception as e:
                    scanner_info.error = f"{type(e).__name__}: {str(e)}"
                    logger.error(f"Unexpected error initializing scanner {scanner_name}: {scanner_info.error}")
                    logger.debug(f"Stack trace for {scanner_name}:\n{traceback.format_exc()}")
            
            self.scanners[scanner_name] = scanner_info
    
    def get_scanner(self, scanner_name: str) -> Optional[Any]:
        """Get a scanner instance if available"""
        scanner_info = self.scanners.get(scanner_name)
        if scanner_info and scanner_info.is_available:
            return scanner_info.instance
        return None
    
    def is_scanner_available(self, scanner_name: str) -> bool:
        """Check if a scanner is available"""
        scanner_info = self.scanners.get(scanner_name)
        return scanner_info.is_available if scanner_info else False
    
    def get_available_scanners(self) -> Dict[str, Any]:
        """Get all available scanner instances"""
        return {
            name: info.instance 
            for name, info in self.scanners.items() 
            if info.is_available
        }
    
    def get_scanner_status(self) -> Dict[str, Dict[str, Any]]:
        """Get status of all scanners"""
        return {
            name: {
                'available': info.is_available,
                'error': info.error,
                'module_path': self.SCANNER_DEFINITIONS[name]['module_path'],
                'class_name': self.SCANNER_DEFINITIONS[name]['class_name']
            }
            for name, info in self.scanners.items()
        }


# Global scanner manager instance
# Note: This instance maintains mutable state. In multi-threaded environments,
# consider using threading locks or creating per-request instances.
scanner_manager = ScannerManager()