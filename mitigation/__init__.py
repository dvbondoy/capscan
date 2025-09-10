"""
Mitigation Engine Module for CapScan
Provides AI-powered mitigation recommendations and workflows.
"""

from .engine import MitigationEngine
from .templates import MitigationTemplates
from .workflows import MitigationWorkflow

__all__ = [
    'MitigationEngine',
    'MitigationTemplates', 
    'MitigationWorkflow'
]
