import json
from pathlib import Path
from typing import List, Dict, Any

from scan2hive.log import LoggerManager

logger = LoggerManager.get_logger()


class JsonLoadingMixin:
    @staticmethod
    def _load_json(path: Path) -> List[Dict[str, Any]]:
        try:
            with open(path, "r") as f:
                data = json.load(f)
        except:
            try:
                with open(path, "r") as f:
                    data = [json.loads(line) for line in f]
            except:
                logger.error(f"cannot load json from file '{path.as_posix()}'.")
                exit(1)
        return data

    @staticmethod
    def _validate_json_data(json_data: List[Dict[str, Any]]) -> bool:
        raise NotImplementedError
