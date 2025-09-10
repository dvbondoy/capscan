"""
Compliance Framework Module for CapScan
Provides compliance checking against various industry standards.
"""

from .frameworks import ComplianceFramework, get_supported_standards
from .analyzers import ComplianceAnalyzer
from .templates import ComplianceTemplates

__all__ = [
    'ComplianceFramework',
    'ComplianceAnalyzer', 
    'ComplianceTemplates',
    'get_supported_standards'
]
