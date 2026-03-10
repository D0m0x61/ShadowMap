import json
import os
from datetime import datetime
from typing import Any, Dict

from shadowmap.config import Config
from shadowmap.utils.logger import get_logger

logger = get_logger(__name__)


def save(data: Dict[str, Any], target: str) -> str:
    os.makedirs(Config.OUTPUT_DIR, exist_ok=True)
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    name = target.replace(".", "_").replace("/", "_").replace(":", "_")
    path = os.path.join(Config.OUTPUT_DIR, f"report_{name}_{ts}.json")

    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str, ensure_ascii=False)

    logger.info(f"[output] JSON: {path}")
    return os.path.abspath(path)
