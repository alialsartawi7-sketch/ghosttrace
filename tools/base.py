"""
Base Tool Adapter — Plugin Interface
All OSINT tools must extend this class
"""
from abc import ABC, abstractmethod
from typing import Any, Optional


class ToolAdapter(ABC):
    """Base class for all OSINT tool integrations"""

    name: str = "base"
    cmd: str = "base"
    result_type: str = "generic"
    description: str = ""

    @abstractmethod
    def build_command(self, target: str, **options: Any) -> list[str]:
        """Build the command line arguments. Returns list of strings."""
        pass

    @abstractmethod
    def parse_line(self, line: str, context: dict) -> list[dict[str, Any]]:
        """
        Parse a single output line.
        Returns list of dicts: [{"value": ..., "source": ..., "type": ..., "extra": ...}]
        Or empty list if line is not a result.
        Context dict can hold state between calls (e.g., current_section).
        """
        pass

    def should_ignore(self, value: str) -> bool:
        """Override to filter out known false positives"""
        return False

    def get_confidence(self, value: str, source: Optional[str] = None) -> float:
        """Override to provide confidence score (0.0 - 1.0)"""
        return 0.5

    def get_env(self) -> Optional[dict[str, str]]:
        """Override to inject env vars (e.g. API keys) into subprocess. Returns dict or None."""
        return None
