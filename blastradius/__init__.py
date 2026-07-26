"""BlastRadius — scan a repo for auto-execution points an AI agent can trigger."""
from .scanner import scan, ScanResult
from .models import Finding, Severity, Amplifier

__version__ = "0.1.0"
__all__ = ["scan", "ScanResult", "Finding", "Severity", "Amplifier", "__version__"]
