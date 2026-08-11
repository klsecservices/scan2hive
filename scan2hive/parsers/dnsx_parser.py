import itertools
import json
import re
from argparse import ArgumentParser
from dataclasses import dataclass
from ipaddress import IPv4Address
from pathlib import Path
from typing import ClassVar, Self, Callable, List, Optional, Dict, Any

from hive_library import HiveLibrary

from scan2hive.hive.custom_rest_api import CustomHost
from scan2hive.hive.result import HiveResult
from scan2hive.log import LoggerManager
from scan2hive.parsers.base import ScannerFileParser, register_parser
from scan2hive.parsers.enums import ToolType
from scan2hive.parsers.helper import ArgumentsHelper, register_arg_helper

logger = LoggerManager.get_logger()


@dataclass
class DnsxResponse:
    ip: IPv4Address
    hostname: str


@dataclass
class DnsxEntry:
    hostname: str
    ips: List[str]

    @classmethod
    def from_json(cls, data: Dict[str, Any]) -> Optional[Self]:
        if "host" not in data or "a" not in data:
            return None

        hostname = data["host"]
        ips = data["a"]

        if not hostname or not ips:
            return None

        return cls(hostname=hostname, ips=ips)

    @classmethod
    def from_txt_line(cls, line: str) -> Optional[Self]:
        match = re.match(r'^([^\s]+)\s+\[A\]\s+\[([^\]]+)\]', line)
        if not match:
            return None

        hostname = match.group(1)
        ips = [ip.strip() for ip in match.group(2).split(',')]

        return cls(hostname=hostname, ips=ips)


@register_parser
class DnsxParser(ScannerFileParser):
    Type: ClassVar[ToolType] = ToolType.Dnsx

    def __init__(self, input_file: Path, tag: str, *args, **kwargs):
        super().__init__(input_file, tag, *args, **kwargs)
        self._raw_text: str = None
        self._dnsx_responses: List[DnsxResponse] = None

    def _consume_source(self):
        try:
            self._raw_text = self._input_file.read_text(encoding='utf-8')
        except Exception as e:
            logger.error(f"Cannot read dnsx output file '{self._input_file.as_posix()}'. Exception: {e}")
            exit(1)

    def _validate_source(self) -> bool:
        if not self._raw_text:
            return False

        # Try JSON format first
        if self._is_json_format():
            logger.debug("File looks like dnsx JSON output")
            return True

        # Try TXT format
        if self._is_txt_format():
            logger.debug("File looks like dnsx TXT output")
            return True

        logger.error("File does not appear to be dnsx output")
        return False

    def _is_json_format(self) -> bool:
        for line in self._raw_text.strip().split('\n'):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                if "host" in data:
                    return True
            except json.JSONDecodeError:
                return False
        return False

    def _is_txt_format(self) -> bool:
        for line in self._raw_text.strip().split('\n'):
            line = line.strip()
            if not line:
                continue
            if DnsxEntry.from_txt_line(line):
                return True
        return False

    def _parse_json_format(self) -> List[DnsxEntry]:
        entries = []
        for line in self._raw_text.strip().split('\n'):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                entry = DnsxEntry.from_json(data)
                if entry:
                    entries.append(entry)
            except:
                continue
        return entries

    def _parse_txt_format(self) -> List[DnsxEntry]:
        entries = []
        for line in self._raw_text.strip().split('\n'):
            line = line.strip()
            if not line:
                continue
            entry = DnsxEntry.from_txt_line(line)
            if entry:
                entries.append(entry)
        return entries

    def _entries_to_responses(self, entries: List[DnsxEntry]) -> List[DnsxResponse]:
        responses = []
        for entry in entries:
            for ip_str in entry.ips:
                try:
                    ip = IPv4Address(ip_str)
                    responses.append(DnsxResponse(ip=ip, hostname=entry.hostname))
                except:
                    continue
        return responses

    def _parse_source(self):
        if self._is_json_format():
            entries = self._parse_json_format()
        else:
            entries = self._parse_txt_format()

        self._dnsx_responses = self._entries_to_responses(entries)

    def _build_hive_hosts(self) -> List[CustomHost]:
        hosts: List[CustomHost] = []

        ip_sorted = sorted(self._dnsx_responses, key=lambda it: it.ip)
        grouped_by_ip = itertools.groupby(ip_sorted, key=lambda it: it.ip)

        for ip, ip_group in grouped_by_ip:
            host = CustomHost(ip=ip)
            host.names = [HiveLibrary.Host.Name(hostname=it.hostname,tags=[HiveLibrary.Tag(name=self._tag)]) for it in
                          ip_group]
            hosts.append(host)

        return hosts

    def _produce_output(self) -> HiveResult:
        return HiveResult(self._build_hive_hosts())


@register_arg_helper(typ=ToolType.Dnsx)
class DnsxArgumentsHelper(ArgumentsHelper):
    @staticmethod
    def setup_args(subparsers, add_common: Callable) -> ArgumentParser:
        dnsx_parser: ArgumentParser = subparsers.add_parser(
            ToolType.Dnsx.as_str,
            help="Import dnsx JSON or TXT result in Hive project",
        )

        add_common(dnsx_parser)

        return dnsx_parser
