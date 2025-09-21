import logging
from typing import Tuple

from models import LicenseClassification, RiskLevel, License, LicenseWithClassification

logger = logging.getLogger(__name__)

# License mappings based on the classification table
LICENSE_MAPPINGS = {
    # Notice licenses (Low/Allowed)
    LicenseClassification.NOTICE: {
        'licenses': [
            'mit', 'apache-2.0', 'apache', 'bsd-2-clause', 'bsd-3-clause', 'bsd', 
            'artistic-2.0', 'isc', 'openssl', 'zlib', 'artistic', 'bsd-2', 'bsd-3'
        ],
        'risk_level': RiskLevel.LOW
    },
    
    # Permissive licenses (typically empty by default)
    LicenseClassification.PERMISSIVE: {
        'licenses': [],
        'risk_level': RiskLevel.LOW
    },
    
    # Unencumbered licenses (Very Low/Allowed)
    LicenseClassification.UNENCUMBERED: {
        'licenses': [
            'cc0-1.0', 'unlicense', '0bsd', 'cc0', 'public domain', 'wtfpl'
        ],
        'risk_level': RiskLevel.VERY_LOW
    },
    
    # Restricted licenses (Medium)
    LicenseClassification.RESTRICTED: {
        'licenses': [
            'gpl', 'gpl-2.0', 'gpl-3.0', 'lgpl', 'lgpl-2.1', 'lgpl-3.0',
            'agpl', 'agpl-3.0', 'gpl-2.0+', 'gpl-3.0+', 'lgpl-2.1+', 'lgpl-3.0+'
        ],
        'risk_level': RiskLevel.MEDIUM
    },
    
    # Reciprocal licenses (Medium)
    LicenseClassification.RECIPROCAL: {
        'licenses': [
            'mpl-2.0', 'mpl', 'epl-2.0', 'epl', 'cddl-1.0', 'cddl', 'eupl-1.2',
            'mozilla public license', 'eclipse public license', 'common development and distribution license'
        ],
        'risk_level': RiskLevel.MEDIUM
    },
    
    # Forbidden licenses (High/Forbidden)
    LicenseClassification.FORBIDDEN: {
        'licenses': [
            'agpl', 'cc-by-nc', 'cc-by-nc-sa', 'cc-by-nc-nd', 'wtfpl',
            'json', 'redis source available license', 'bsl', 'elastic license'
        ],
        'risk_level': RiskLevel.HIGH
    }
}

class LicenseClassifier:
    """
    Classifier for software licenses based on risk level and usage restrictions.
    """

    def classify_license(self, license: License) -> LicenseWithClassification:
        """
        Classify a license object and return a LicenseWithClassification object.
        
        Args:
            license: License object to classify
            
        Returns:
            LicenseWithClassification object with classification and risk level
        """
        classification, risk_level = self._classify_license_name(license.name)
        return LicenseWithClassification(
            license=license,
            classification=classification,
            risk_level=risk_level
        )

    def _classify_license_name(self, license_name: str) -> Tuple[LicenseClassification, RiskLevel]:
        """
        Classify a license based on its name.
        
        Args:
            license_name: Name of the license to classify
            
        Returns:
            Tuple of (LicenseClassification, RiskLevel)
        """
        if not license_name or license_name.lower().strip() in ['', 'unknown', 'none']:
            return LicenseClassification.UNKNOWN, RiskLevel.UNKNOWN
        
        # Normalize license name for comparison  
        normalized_name = license_name.lower().strip()
        
        # Check each classification category
        for classification, data in LICENSE_MAPPINGS.items():
            for license_pattern in data['licenses']:
                if self._matches_license_pattern(normalized_name, license_pattern):
                    logger.debug(f"Classified '{license_name}' as {classification.value} with risk {data['risk_level'].value}")
                    return classification, data['risk_level']
        
        # If no match found, return unknown
        logger.warning(f"Unknown license classification for: '{license_name}'")
        return LicenseClassification.UNKNOWN, RiskLevel.UNKNOWN

    def _matches_license_pattern(self, normalized_name: str, pattern: str) -> bool:
        """
        Check if a normalized license name matches a pattern.
        
        Args:
            normalized_name: Normalized license name
            pattern: License pattern to match against
            
        Returns:
            True if the license matches the pattern
        """
        # Exact match
        if normalized_name == pattern:
            return True
        
        # Check if the pattern is contained in the name
        if pattern in normalized_name:
            return True
        
        # Check for version variations (e.g., "apache-2.0" matches "apache")
        if pattern == 'apache' and normalized_name.startswith('apache'):
            return True
        if pattern == 'bsd' and ('bsd' in normalized_name):
            return True
        if pattern == 'gpl' and normalized_name.startswith('gpl'):
            return True
        if pattern == 'lgpl' and normalized_name.startswith('lgpl'):
            return True
        if pattern == 'mpl' and normalized_name.startswith('mpl'):
            return True
        if pattern == 'epl' and normalized_name.startswith('epl'):
            return True
        if pattern == 'cddl' and normalized_name.startswith('cddl'):
            return True
        
        return False
