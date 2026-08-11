import json
from pathlib import Path
from typing import List, Dict, Any

from scan2hive.log import LoggerManager

logger = LoggerManager.get_logger()


class JsonLoadingMixin:
    @staticmethod
    def _load_json(path: Path) -> List[Dict[str, Any]]:
        with open(path, "rb") as f:
            raw_data = f.read().decode("utf-8")
            if raw_data[0] == "[" and raw_data[-1] == "]":
                # json case
                try:
                    data = json.loads(raw_data)
                except:
                    logger.error(f"cannot load json from file '{path.as_posix()}'.")
                    exit(1)
            elif raw_data[0] == "{":
                # jsonl case
                try:
                    data = [json.loads(line) for line in raw_data.splitlines()]
                except:
                    logger.error(f"cannot load json from file '{path.as_posix()}'.")
                    exit(1)
            else:
                logger.error(f"This file is not json or jsonl:'{path.as_posix()}'.")
                exit(1)
        return data

    @staticmethod
    def _validate_json_data(json_data: List[Dict[str, Any]]) -> bool:
        raise NotImplementedError
