"""Google Dorks Generator — Builds targeted search queries for manual use"""
from tools.base import ToolAdapter

class GoogleDorksAdapter(ToolAdapter):
    name = "GoogleDorks"
    cmd = "echo"  # No real command — generates queries locally
    result_type = "dork"
    description = "Generates Google dork queries for manual OSINT"

    DORK_TEMPLATES = [
        # File discovery
        {"category": "Sensitive Files", "dorks": [
            ('site:{target} filetype:pdf', "PDF documents"),
            ('site:{target} filetype:xls OR filetype:xlsx', "Excel spreadsheets"),
            ('site:{target} filetype:doc OR filetype:docx', "Word documents"),
            ('site:{target} filetype:sql', "SQL database dumps"),
            ('site:{target} filetype:log', "Log files"),
            ('site:{target} filetype:env', "Environment config files"),
            ('site:{target} filetype:xml', "XML configuration"),
            ('site:{target} filetype:csv', "CSV data files"),
        ]},
        # Admin & Login
        {"category": "Admin & Login Pages", "dorks": [
            ('site:{target} inurl:admin', "Admin panels"),
            ('site:{target} inurl:login', "Login pages"),
            ('site:{target} inurl:dashboard', "Dashboards"),
            ('site:{target} inurl:cpanel', "cPanel access"),
            ('site:{target} intitle:"admin" OR intitle:"login"', "Auth pages by title"),
        ]},
        # Sensitive info
        {"category": "Sensitive Information", "dorks": [
            ('site:{target} "password" OR "passwd" OR "credentials"', "Password references"),
            ('site:{target} "confidential" OR "internal use only"', "Confidential docs"),
            ('site:{target} "api_key" OR "apikey" OR "api key"', "API key leaks"),
            ('site:{target} "private key" OR "BEGIN RSA"', "Private key exposure"),
            ('site:{target} "phpinfo" OR "phpMyAdmin"', "PHP info/admin"),
        ]},
        # Infrastructure
        {"category": "Infrastructure Discovery", "dorks": [
            ('site:{target} inurl:wp-content', "WordPress detection"),
            ('site:{target} inurl:wp-admin', "WordPress admin"),
            ('site:{target} intitle:"index of /"', "Directory listings"),
            ('site:{target} inurl:.git', "Git repository exposure"),
            ('site:{target} inurl:.env', "Environment files"),
            ('site:{target} inurl:backup', "Backup files"),
        ]},
        # Error pages & debug
        {"category": "Error & Debug Pages", "dorks": [
            ('site:{target} intitle:"500 Internal Server Error"', "Server errors"),
            ('site:{target} "stack trace" OR "traceback"', "Debug info leaks"),
            ('site:{target} "Warning:" "on line"', "PHP warnings"),
            ('site:{target} "DEBUG = True" OR "debug mode"', "Debug mode enabled"),
        ]},
    ]

    def build_command(self, target, **opts):
        # We don't actually run a command — we generate queries locally
        return ["echo", "generating_dorks"]

    def parse_line(self, line, context):
        return []

    def generate(self, target):
        """Generate all dork queries for a target domain"""
        results = []
        for category in self.DORK_TEMPLATES:
            cat_name = category["category"]
            for dork_template, description in category["dorks"]:
                query = dork_template.replace("{target}", target)
                url = f"https://www.google.com/search?q={query.replace(' ', '+')}"
                results.append({
                    "value": query,
                    "source": self.name,
                    "type": "dork",
                    "confidence": 0.5,  # Queries, not confirmed findings
                    "extra": f"{cat_name}: {description}",
                    "url": url
                })
        return results
