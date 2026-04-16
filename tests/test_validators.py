"""Tests for utils/validators.py"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest
from utils.validators import Validators, ValidationError


# ═══════════ DOMAIN ═══════════

class TestDomain:
    @pytest.mark.parametrize("inp,expected", [
        ("example.com", "example.com"),
        ("sub.example.com", "sub.example.com"),
        ("EXAMPLE.COM", "example.com"),
        ("deep.sub.example.co.uk", "deep.sub.example.co.uk"),
    ])
    def test_valid_domains(self, inp, expected):
        assert Validators.domain(inp) == expected

    @pytest.mark.parametrize("inp,expected", [
        ("https://example.com", "example.com"),
        ("http://example.com/", "example.com"),
        ("https://www.example.com/path", "example.com"),
        ("user@example.com", "example.com"),
    ])
    def test_protocol_stripping(self, inp, expected):
        assert Validators.domain(inp) == expected

    @pytest.mark.parametrize("inp", [
        "", "   ", "not valid!", "hello", "../etc/passwd",
        "a" * 300, ";rm -rf /", "example..com",
    ])
    def test_invalid_domains(self, inp):
        with pytest.raises(ValidationError):
            Validators.domain(inp)

    def test_path_traversal_blocked(self):
        with pytest.raises(ValidationError):
            Validators.domain("../../../etc/shadow")

    def test_empty_raises(self):
        with pytest.raises(ValidationError, match="cannot be empty"):
            Validators.domain("")


# ═══════════ USERNAME ═══════════

class TestUsername:
    @pytest.mark.parametrize("inp,expected", [
        ("john_doe", "john_doe"),
        ("user123", "user123"),
        ("a.b-c", "a.b-c"),
        ("@twitter_user", "twitter_user"),
    ])
    def test_valid_usernames(self, inp, expected):
        assert Validators.username(inp) == expected

    @pytest.mark.parametrize("inp", [
        "", "rm -rf /", "user name", "a" * 65,
        "user;ls", "user|cat",
    ])
    def test_invalid_usernames(self, inp):
        with pytest.raises(ValidationError):
            Validators.username(inp)

    def test_leading_at_stripped(self):
        assert Validators.username("@johndoe") == "johndoe"

    def test_too_long(self):
        with pytest.raises(ValidationError):
            Validators.username("a" * 65)


# ═══════════ FILEPATH ═══════════

class TestFilepath:
    def test_valid_absolute(self):
        assert Validators.filepath("/home/kali/photo.jpg") == "/home/kali/photo.jpg"

    def test_traversal_blocked(self):
        with pytest.raises(ValidationError, match="traversal"):
            Validators.filepath("../../etc/passwd")

    @pytest.mark.parametrize("inp", [
        "/etc/shadow", "/root/.bashrc", "/home/user/.ssh/id_rsa",
    ])
    def test_forbidden_paths(self, inp):
        with pytest.raises(ValidationError):
            Validators.filepath(inp)

    def test_relative_rejected(self):
        with pytest.raises(ValidationError):
            Validators.filepath("relative.txt")


# ═══════════ CLI COMMAND ═══════════

class TestCliCommand:
    def test_allowed_tool(self):
        parts = Validators.cli_command("theHarvester -d test.com -b crtsh")
        assert parts[0].lower() == "theharvester"

    def test_forbidden_tool(self):
        with pytest.raises(ValidationError, match="not allowed"):
            Validators.cli_command("rm -rf /")

    def test_empty_command(self):
        with pytest.raises(ValidationError):
            Validators.cli_command("")

    def test_sherlock_valid(self):
        parts = Validators.cli_command("sherlock johndoe")
        assert parts == ["sherlock", "johndoe"]

    def test_maigret_valid(self):
        parts = Validators.cli_command("maigret testuser --site Instagram")
        assert parts[0] == "maigret"

    def test_invalid_argument_rejected(self):
        with pytest.raises(ValidationError):
            Validators.cli_command("sherlock user;ls")


# ═══════════ DETECT INPUT TYPE ═══════════

class TestDetectInputType:
    def test_domain(self):
        t, v = Validators.detect_input_type("example.com")
        assert t == "domain"

    def test_email_extracts_domain(self):
        t, v = Validators.detect_input_type("admin@example.com")
        assert t == "email"
        assert v == "example.com"

    def test_username_fallback(self):
        t, v = Validators.detect_input_type("john_doe")
        assert t == "username"

    def test_empty(self):
        t, v = Validators.detect_input_type("")
        assert t == "unknown"
