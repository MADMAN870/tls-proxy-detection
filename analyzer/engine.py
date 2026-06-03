from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import List, Optional

from analyzer.patterns import (
    PatternMatch, compile_patterns, scan_content, check_extension,
    check_domain, check_content_length, compile_domain_patterns,
)
from alerts.manager import AlertManager
from loguru import logger


@dataclass
class TrafficRecord:
    type: str
    method: Optional[str] = None
    host: Optional[str] = None
    port: Optional[int] = None
    path: Optional[str] = None
    url: Optional[str] = None
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    content_length: int = 0
    content: Optional[str] = None
    timestamp: Optional[float] = None


@dataclass
class AnalysisResult:
    risk_score: float
    severity: str
    findings: List[dict]
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class AnalysisEngine:
    def __init__(self, alert_manager: AlertManager, config: dict):
        self.alert_manager = alert_manager
        self.config = config
        self.thresholds = config.get("risk_scoring", {}).get("thresholds", {})
        self._patterns = compile_patterns(config)
        sus_conf = config.get("suspicious", {})
        self._extensions = set(sus_conf.get("extensions", []))
        self._domains = compile_domain_patterns(sus_conf.get("domains", []))
        self._volume_threshold = sus_conf.get("high_volume_threshold", 5 * 1024 * 1024)

    @property
    def patterns(self) -> list:
        rules = []
        for name, info in self._patterns.items():
            rules.append({
                "name": name.replace("_", " ").title(),
                "pattern": " | ".join(r.pattern for r in info["regexes"]),
                "severity": info["severity"],
                "type": "data_leak",
                "enabled": True,
                "description": f"Detects {name.replace('_', ' ')} in request/response bodies",
            })
        if self._extensions:
            rules.append({
                "name": "Suspicious Extension",
                "pattern": "\\.(" + "|".join(e.lstrip(".") for e in self._extensions) + ")$",
                "severity": 0.15,
                "type": "suspicious_file",
                "enabled": True,
                "description": "Detects downloads of executable or archive files",
            })
        if self._domains:
            rules.append({
                "name": "Suspicious Domain",
                "pattern": ", ".join(self.config.get("suspicious", {}).get("domains", [])),
                "severity": 0.20,
                "type": "suspicious_destination",
                "enabled": True,
                "description": "Detects connections to data exfiltration destinations",
            })
        rules.append({
            "name": "High Volume Transfer",
            "pattern": f"content_length > {self._volume_threshold} bytes",
            "severity": 0.15,
            "type": "data_exfiltration",
            "enabled": True,
            "description": "Flags large payloads that may indicate bulk data exfiltration",
        })
        return rules

    def analyze(self, record: TrafficRecord) -> AnalysisResult:
        findings: List[PatternMatch] = []
        total_score = 0.0
        content = record.content or ""
        url = record.url or ""
        host = record.host or ""

        if content:
            findings.extend(scan_content(content, "body", self._patterns))

        ext_match = check_extension(url, self._extensions)
        if ext_match:
            findings.append(ext_match)

        domain_match = check_domain(host, self._domains)
        if domain_match:
            findings.append(domain_match)

        size_match = check_content_length(record.content_length, self._volume_threshold)
        if size_match:
            findings.append(size_match)

        for finding in findings:
            total_score += finding.severity

        severity = self._classify(total_score)

        result = AnalysisResult(
            risk_score=round(total_score, 4),
            severity=severity,
            findings=[asdict(f) for f in findings],
        )

        if findings:
            logger.warning(
                f"[{severity.upper()}] {record.host}{record.path} "
                f"risk={total_score:.2f} findings={len(findings)}"
            )
            self.alert_manager.trigger({
                "risk_score": result.risk_score,
                "severity": result.severity,
                "findings": result.findings,
                "url": url,
                "host": host,
                "path": record.path,
                "method": record.method,
                "timestamp": result.timestamp,
            })

        return result

    def _classify(self, score: float) -> str:
        if score >= self.thresholds.get("high", 3.0):
            return "critical"
        elif score >= self.thresholds.get("medium", 2.0):
            return "high"
        elif score >= self.thresholds.get("low", 1.0):
            return "medium"
        return "low"
