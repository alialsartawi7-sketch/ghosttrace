"""
Base Tool Adapter — Plugin Interface
All OSINT tools must extend this class
"""
from abc import ABC, abstractmethod

class ToolAdapter(ABC):
    """Base class for all OSINT tool integrations"""

    name = "base"           # Tool display name
    cmd = "base"            # System command
    result_type = "generic" # email, username, metadata, subdomain
    description = ""

    @abstractmethod
    def build_command(self, target, **options):
        """Build the command line arguments. Returns list of strings."""
        pass

    @abstractmethod
    def parse_line(self, line, context):
        """
        Parse a single output line.
        Returns list of dicts: [{"value": ..., "source": ..., "type": ..., "extra": ...}]
        Or empty list if line is not a result.
        Context dict can hold state between calls (e.g., current_section).
        """
        pass

    def should_ignore(self, value):
        """Override to filter out known false positives"""
        return False

    def get_confidence(self, value, source=None):
        """Override to provide confidence score (0.0 - 1.0)"""
        return 0.5

    def get_env(self):
        """Override to inject env vars (e.g. API keys) into subprocess. Returns dict or None."""
        return None
