"""
Tool Registry — Plugin system for OSINT tools
Add new tools by creating an adapter and registering it here
"""
from tools.harvester import HarvesterAdapter
from tools.sherlock_tool import SherlockAdapter
from tools.exiftool import ExifToolAdapter
from tools.maigret_tool import MaigretAdapter
from tools.phoneinfoga_tool import PhoneInfogaAdapter
from tools.whois_tool import WhoisAdapter
from tools.dns_records import DNSRecordsAdapter
from tools.ssl_cert import SSLCertAdapter
from tools.google_dorks import GoogleDorksAdapter
from core.engine import ExecutionEngine
from utils.logger import log

class ToolRegistry:
    _tools = {}

    @classmethod
    def register(cls, adapter_class):
        instance = adapter_class()
        cls._tools[instance.name.lower()] = instance
        log.debug(f"Registered tool: {instance.name}")

    @classmethod
    def get(cls, name):
        return cls._tools.get(name.lower())

    @classmethod
    def all(cls):
        return cls._tools

    @classmethod
    def check_all(cls):
        status = {}
        for name, tool in cls._tools.items():
            status[tool.name] = ExecutionEngine.check_tool(tool.name, tool.cmd)
        # PDF engine: weasyprint (Python) or wkhtmltopdf (system)
        try:
            import weasyprint
            status["PDF Engine"] = {"installed": True, "path": "weasyprint (Python)"}
        except ImportError:
            wk = ExecutionEngine.check_tool("wkhtmltopdf")
            if wk["installed"]:
                status["PDF Engine"] = {"installed": True, "path": wk["path"]}
            else:
                status["PDF Engine"] = {"installed": False, "path": None}
        return status

    @classmethod
    def init(cls):
        cls.register(HarvesterAdapter)
        cls.register(SherlockAdapter)
        cls.register(MaigretAdapter)
        cls.register(ExifToolAdapter)
        cls.register(PhoneInfogaAdapter)
        cls.register(WhoisAdapter)
        cls.register(DNSRecordsAdapter)
        cls.register(SSLCertAdapter)
        cls.register(GoogleDorksAdapter)
        log.info(f"Tool registry: {len(cls._tools)} tools loaded")
