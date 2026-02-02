from dataclasses import dataclass
from datetime import datetime
from hive_library import HiveLibrary
from ipaddress import IPv4Address
from pathlib import Path
from typing import List

from scan2hive.hive.custom_rest_api import CustomHostSchema


@dataclass
class HiveResult:
    hosts: List[HiveLibrary.Host]

    def to_str(self) -> str:
        return "\n".join(map(str, self.hosts))

    def to_json(self) -> str:
        hosts_schema: CustomHostSchema = CustomHostSchema(many=True)
        return hosts_schema.dump(self.hosts)


@dataclass
class ScreenshotDescriptor:
    ip: IPv4Address
    port: int
    screenshot_data: bytes | None


@dataclass
class GowitnessHiveResult(HiveResult):
    screendhot_descriptors: List[ScreenshotDescriptor] | None
