"""wopt — mini audit de sécurité web en ligne de commande."""

__version__ = "0.1.0"

from wopt.core.scanner import scan

__all__ = ["scan", "__version__"]
