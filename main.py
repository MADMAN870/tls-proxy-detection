import os
import signal
import sys

import yaml
from pathlib import Path
from loguru import logger

from alerts.manager import AlertManager
from analyzer.engine import AnalysisEngine
from web.app import create_app
from storage.log_writer import TrafficLogger

logger.add("/data/app.log", rotation="10 MB", retention="30 days", level="INFO")

CONFIG_PATH = Path("/app/config/config.yaml")


def _resolve_env(value):
    if isinstance(value, str) and value.startswith("${") and value.endswith("}"):
        inner = value[2:-1]
        if ":-" in inner:
            key, default = inner.split(":-", 1)
            return os.environ.get(key, default)
        return os.environ.get(inner, "")
    return value


def _resolve_config(obj):
    if isinstance(obj, dict):
        return {k: _resolve_config(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_resolve_config(v) for v in obj]
    if isinstance(obj, str):
        return _resolve_env(obj)
    return obj


def load_config() -> dict:
    with open(CONFIG_PATH) as f:
        raw = yaml.safe_load(f)
    return _resolve_config(raw)


def main():
    config = load_config()
    logger.info("Starting TLS Inspection Proxy Analyzer v2.0.0")

    alert_manager = AlertManager(config)
    analyzer = AnalysisEngine(alert_manager, config)
    traffic_logger = TrafficLogger()

    app = create_app(alert_manager, analyzer, config, traffic_logger)

    def shutdown_handler(signum, frame):
        logger.info("Shutting down...")
        alert_manager.close()
        traffic_logger.close()
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown_handler)
    signal.signal(signal.SIGINT, shutdown_handler)

    import uvicorn
    host = config.get("server", {}).get("host", "0.0.0.0")
    port = config.get("server", {}).get("port", 8000)
    uvicorn.run(app, host=host, port=port, log_level="info", lifespan="on")


if __name__ == "__main__":
    main()
