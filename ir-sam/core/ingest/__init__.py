"""Ingestion layer: detector output -> unified IRSAMFinding."""

from .unified import IRSAMFinding, load_findings, validate_finding

__all__ = ["IRSAMFinding", "load_findings", "validate_finding"]
