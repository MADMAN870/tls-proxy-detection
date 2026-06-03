import re
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class PatternMatch:
    pattern_name: str
    pattern_type: str
    matches: List[str]
    severity: float
    location: str


def compile_patterns(config: dict) -> dict:
    patterns = {}
    for name, cfg in config.get("patterns", {}).items():
        if not cfg.get("enabled", True):
            continue
        severity = cfg.get("severity", 0.10)
        compiled = []
        for raw in cfg.get("patterns", []):
            try:
                compiled.append(re.compile(raw))
            except re.error as e:
                print(f"Warning: invalid regex for {name}: {e}")
                continue
        if compiled:
            patterns[name] = {"regexes": compiled, "severity": severity}
    return patterns


def scan_content(content: str, source: str, compiled_patterns: dict) -> List[PatternMatch]:
    results = []
    if not content or not isinstance(content, str):
        return results
    for name, info in compiled_patterns.items():
        for regex in info["regexes"]:
            matches = regex.findall(content)
            if matches:
                results.append(PatternMatch(
                    pattern_name=name,
                    pattern_type="data_leak",
                    matches=list(set(matches)),
                    severity=info["severity"],
                    location=source,
                ))
    return results


def check_extension(url: str, suspicious_extensions: set) -> Optional[PatternMatch]:
    lower = url.lower()
    for ext in suspicious_extensions:
        if lower.endswith(ext):
            return PatternMatch(
                pattern_name="suspicious_extension",
                pattern_type="suspicious_file",
                matches=[ext],
                severity=0.15,
                location="url",
            )
    return None


def compile_domain_patterns(domains: List[str]) -> List[re.Pattern]:
    compiled = []
    for d in domains:
        try:
            compiled.append(re.compile(re.escape(d) + r"\.", re.I))
        except re.error:
            continue
    compiled.append(re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$"))
    return compiled


def check_domain(host: str, domain_patterns: List[re.Pattern]) -> Optional[PatternMatch]:
    for pattern in domain_patterns:
        if pattern.search(host):
            return PatternMatch(
                pattern_name="suspicious_domain",
                pattern_type="suspicious_destination",
                matches=[host],
                severity=0.20,
                location="host",
            )
    return None


def check_content_length(length: int, threshold: int) -> Optional[PatternMatch]:
    if length > threshold:
        return PatternMatch(
            pattern_name="high_volume_transfer",
            pattern_type="data_exfiltration",
            matches=[f"{length} bytes"],
            severity=0.15,
            location="content_length",
        )
    return None
