"""Tests for the TLS Inspection Proxy analyzer and patterns."""

import json
import re
import tempfile
from pathlib import Path

import pytest
import yaml

from analyzer.patterns import (
    compile_patterns, scan_content, check_extension,
    compile_domain_patterns, check_domain, check_content_length,
)
from analyzer.engine import AnalysisEngine, AnalysisResult, TrafficRecord
from alerts.manager import AlertManager


SAMPLE_CONFIG = {
    "patterns": {
        "credit_card": {
            "enabled": True,
            "severity": 0.30,
            "patterns": [
                r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"
            ],
        },
        "email": {
            "enabled": True,
            "severity": 0.10,
            "patterns": [r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"],
        },
        "api_key": {
            "enabled": True,
            "severity": 0.25,
            "patterns": [
                r"(?i)(?:api[-_]?key|apikey|secret[-_]?key|access[-_]?key)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}['\"]?",
                r"(?i)bearer\s+[A-Za-z0-9_\-=]{20,}",
            ],
        },
        "password": {
            "enabled": True,
            "severity": 0.25,
            "patterns": [r"(?i)(?:password|passwd|pwd)['\"]?\s*[:=]\s*['\"]?[^'\"\s]{4,}['\"]?"],
        },
        "jwt": {
            "enabled": True,
            "severity": 0.20,
            "patterns": [r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"],
        },
        "ssn": {
            "enabled": True,
            "severity": 0.30,
            "patterns": [r"\b\d{3}-\d{2}-\d{4}\b"],
        },
    },
    "suspicious": {
        "extensions": [".exe", ".dll", ".bat", ".ps1", ".zip", ".rar"],
        "domains": ["pastebin", "ghostbin", "tor2web", "onion", "i2p"],
        "high_volume_threshold": 5 * 1024 * 1024,
    },
    "risk_scoring": {
        "thresholds": {"low": 1.0, "medium": 2.0, "high": 3.0},
    },
    "alerts": {
        "file": False,
        "db_path": ":memory:",
    },
}


# --- Pattern compilation tests ---

class TestCompilePatterns:
    def test_compiles_valid_patterns(self):
        patterns = compile_patterns(SAMPLE_CONFIG)
        assert "credit_card" in patterns
        assert "email" in patterns
        assert len(patterns["credit_card"]["regexes"]) == 1

    def test_skips_disabled_patterns(self):
        config = dict(SAMPLE_CONFIG)
        config["patterns"] = {"credit_card": {"enabled": False, "severity": 0.30, "patterns": [r"\d+"]}}
        patterns = compile_patterns(config)
        assert "credit_card" not in patterns

    def test_skips_invalid_regex(self):
        config = dict(SAMPLE_CONFIG)
        config["patterns"] = {"bad": {"enabled": True, "severity": 0.10, "patterns": [r"[invalid"]}}
        patterns = compile_patterns(config)
        assert "bad" not in patterns


# --- Content scanning tests ---

class TestScanContent:
    def test_detects_credit_card(self):
        patterns = compile_patterns(SAMPLE_CONFIG)
        results = scan_content("My card is 4111111111111111", "body", patterns)
        assert any(r.pattern_name == "credit_card" for r in results)

    def test_detects_email(self):
        patterns = compile_patterns(SAMPLE_CONFIG)
        results = scan_content("Contact: test@example.com", "body", patterns)
        assert any(r.pattern_name == "email" for r in results)

    def test_detects_ssn(self):
        patterns = compile_patterns(SAMPLE_CONFIG)
        results = scan_content("SSN: 123-45-6789", "body", patterns)
        assert any(r.pattern_name == "ssn" for r in results)

    def test_detects_api_key(self):
        patterns = compile_patterns(SAMPLE_CONFIG)
        results = scan_content('api_key = "sk-1234567890abcdef1234567890abcdef"', "body", patterns)
        assert any(r.pattern_name == "api_key" for r in results)

    def test_detects_jwt(self):
        patterns = compile_patterns(SAMPLE_CONFIG)
        results = scan_content("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNqPnd9y1Gk7_Lv1Qw", "body", patterns)
        assert any(r.pattern_name == "jwt" for r in results)

    def test_detects_password(self):
        patterns = compile_patterns(SAMPLE_CONFIG)
        results = scan_content('password = "supersecret123"', "body", patterns)
        assert any(r.pattern_name == "password" for r in results)

    def test_returns_empty_for_clean_content(self):
        patterns = compile_patterns(SAMPLE_CONFIG)
        results = scan_content("Hello, this is clean content.", "body", patterns)
        assert results == []

    def test_handles_none_content(self):
        patterns = compile_patterns(SAMPLE_CONFIG)
        results = scan_content("", "body", patterns)
        assert results == []


# --- Extension check tests ---

class TestCheckExtension:
    def test_detects_exe(self):
        result = check_extension("http://example.com/file.exe", {".exe", ".dll"})
        assert result is not None
        assert result.pattern_name == "suspicious_extension"

    def test_detects_zip(self):
        result = check_extension("http://example.com/archive.zip", {".zip", ".rar"})
        assert result is not None

    def test_returns_none_for_safe_extensions(self):
        result = check_extension("http://example.com/file.pdf", {".exe", ".zip"})
        assert result is None

    def test_case_insensitive(self):
        result = check_extension("http://example.com/file.EXE", {".exe"})
        assert result is not None


# --- Domain check tests ---

class TestCheckDomain:
    def test_detects_pastebin(self):
        patterns = compile_domain_patterns(["pastebin", "ghostbin"])
        result = check_domain("pastebin.com", patterns)
        assert result is not None
        assert result.pattern_name == "suspicious_domain"

    def test_detects_raw_ip(self):
        patterns = compile_domain_patterns([])
        result = check_domain("192.168.1.1", patterns)
        assert result is not None

    def test_returns_none_for_normal_domain(self):
        patterns = compile_domain_patterns(["pastebin"])
        result = check_domain("example.com", patterns)
        assert result is None


# --- Content length check tests ---

class TestCheckContentLength:
    def test_detects_large_payload(self):
        result = check_content_length(6 * 1024 * 1024, 5 * 1024 * 1024)
        assert result is not None
        assert result.pattern_name == "high_volume_transfer"

    def test_returns_none_for_small_payload(self):
        result = check_content_length(1024, 5 * 1024 * 1024)
        assert result is None


# --- Analysis engine integration tests ---

class TestAnalysisEngine:
    @pytest.fixture
    def engine(self):
        am = AlertManager(SAMPLE_CONFIG)
        return AnalysisEngine(am, SAMPLE_CONFIG)

    def test_analyze_clean_traffic(self, engine):
        record = TrafficRecord(
            type="request",
            method="GET",
            host="example.com",
            path="/",
            url="http://example.com/",
            content="Hello world",
            content_length=11,
        )
        result = engine.analyze(record)
        assert result.risk_score == 0.0
        assert result.severity == "low"
        assert result.findings == []

    def test_analyze_leak_traffic(self, engine):
        record = TrafficRecord(
            type="request",
            method="POST",
            host="example.com",
            path="/login",
            url="http://example.com/login",
            content='{"email": "user@example.com", "password": "hunter2"}',
            content_length=55,
        )
        result = engine.analyze(record)
        assert result.risk_score > 0
        assert len(result.findings) >= 2

    def test_patterns_property(self, engine):
        rules = engine.patterns
        assert len(rules) >= 6
        names = [r["name"] for r in rules]
        assert "Credit Card" in names

    def test_severity_classification(self, engine):
        assert engine._classify(0.5) == "low"
        assert engine._classify(1.5) == "medium"
        assert engine._classify(2.5) == "high"
        assert engine._classify(3.5) == "critical"


# --- Alert manager persistence tests ---

class TestAlertManager:
    @pytest.fixture
    def manager(self):
        config = dict(SAMPLE_CONFIG)
        config["alerts"] = {"file": False, "db_path": ":memory:"}
        return AlertManager(config)

    def test_trigger_and_retrieve(self, manager):
        alert = manager.trigger({
            "risk_score": 2.5,
            "severity": "high",
            "findings": [{"pattern_name": "email", "matches": ["test@test.com"]}],
            "url": "http://example.com",
            "host": "example.com",
            "path": "/",
            "method": "GET",
            "timestamp": "2026-01-01T00:00:00",
        })
        assert alert.id == "ALERT-000001"
        assert alert.severity == "high"

        alerts = manager.get_alerts()
        assert len(alerts) == 1

    def test_acknowledge(self, manager):
        alert = manager.trigger({
            "risk_score": 1.0,
            "severity": "low",
            "findings": [],
            "url": "http://example.com",
            "host": "example.com",
        })
        assert alert.acknowledged is False
        ok = manager.acknowledge(alert.id)
        assert ok is True
        alerts = manager.get_alerts()
        assert alerts[0].acknowledged is True

    def test_clear(self, manager):
        manager.trigger({"risk_score": 1.0, "severity": "low", "findings": [], "url": "", "host": "test"})
        manager.trigger({"risk_score": 2.0, "severity": "medium", "findings": [], "url": "", "host": "test"})
        assert len(manager.get_alerts()) == 2
        manager.clear()
        assert len(manager.get_alerts()) == 0

    def test_stats(self, manager):
        manager.trigger({"risk_score": 1.0, "severity": "low", "findings": [], "url": "", "host": "a"})
        manager.trigger({"risk_score": 2.0, "severity": "medium", "findings": [], "url": "", "host": "b"})
        stats = manager.stats()
        assert stats["total_alerts"] == 2
        assert stats["by_severity"]["low"] == 1
        assert stats["by_severity"]["medium"] == 1

    def test_entities(self, manager):
        manager.trigger({"risk_score": 1.5, "severity": "medium", "findings": [], "url": "", "host": "evil.com"})
        entities = manager.get_entities()
        assert len(entities) == 1
        assert entities[0]["host"] == "evil.com"
        assert entities[0]["alerts"] == 1
