import itertools
from argparse import ArgumentParser
from dataclasses import dataclass
from ipaddress import IPv4Address
from pathlib import Path
from typing import ClassVar, Self, Callable, List, Optional, Dict

from hive_library import HiveLibrary

from scan2hive.hive.custom_rest_api import CustomHost
from scan2hive.hive.result import HiveResult
from scan2hive.log import LoggerManager
from scan2hive.parsers.base import ScannerFileParser, register_parser
from scan2hive.parsers.enums import ToolType, DnsRecordType
from scan2hive.parsers.helper import ArgumentsHelper, register_arg_helper

logger = LoggerManager.get_logger()


@dataclass
class DigResponse:
    ip: IPv4Address
    hostname: str


@dataclass
class DnsRecord:
    domain: str
    record_type: DnsRecordType
    value: str

    @classmethod
    def from_line(cls, line: str) -> Optional[Self]:
        # line format: domain TTL IN TYPE value
        parts = line.split()
        if len(parts) < 5:
            return None
        record_type_str = parts[3]
        if record_type_str not in DnsRecordType.allowed_values():
            return None
        return cls(
            domain=parts[0].rstrip('.'),
            record_type=DnsRecordType(record_type_str),
            value=parts[4].rstrip('.')
        )


@register_parser
class DigParser(ScannerFileParser):
    Type: ClassVar[ToolType] = ToolType.Dig

    def __init__(self, input_file: Path, tag: str, *args, **kwargs):
        super().__init__(input_file, tag, *args, **kwargs)
        self._raw_text: str = None
        self._records: List[DnsRecord] = None
        self._dig_responses: List[DigResponse] = None

    def _consume_source(self):
        try:
            self._raw_text = self._input_file.read_text(encoding='utf-8')
        except Exception as e:
            logger.error(f"Cannot read dig output file '{self._input_file.as_posix()}'. Exception: {e}")
            exit(1)

    def _validate_source(self) -> bool:
        if not self._raw_text:
            return False

        for line in self._raw_text.split('\n'):
            line = line.strip()
            if line and not line.startswith(';'):
                record = DnsRecord.from_line(line)
                if record:
                    logger.debug("File contains valid DNS records")
                    return True

        logger.error("File does not contain valid DNS records")
        return False

    def _extract_records(self) -> List[DnsRecord]:
        records = []
        for line in self._raw_text.split('\n'):
            line = line.strip()
            if line and not line.startswith(';'):
                record = DnsRecord.from_line(line)
                if record:
                    records.append(record)
        return records

    @staticmethod
    def _resolve_records(records: List[DnsRecord]) -> List[DigResponse]:
        a_records = filter(
            lambda it: it.record_type == DnsRecordType.A,
            records
        )
        domain_to_ip: Dict[str, IPv4Address | None] = {}
        for record in a_records:
            try:
                domain_to_ip[record.domain] = IPv4Address(record.value)
            except ValueError:
                domain_to_ip[record.domain] = None

        cname_records = filter(
            lambda it: it.record_type == DnsRecordType.CNAME,
            records
        )
        cnames: Dict[str, str] = {it.domain: it.value for it in cname_records}

        while cnames:
            resolved = [source for source, target in cnames.items() if target in domain_to_ip]
            if not resolved:
                break
            for source in resolved:
                domain_to_ip[source] = domain_to_ip[cnames[source]]
                del cnames[source]

        return [DigResponse(ip=ip, hostname=hostname) for hostname, ip in domain_to_ip.items() if ip is not None]

    def _parse_source(self):
        self._records = self._extract_records()
        self._dig_responses = self._resolve_records(self._records)

    def _build_hive_hosts(self) -> List[CustomHost]:
        hosts: List[CustomHost] = []

        ip_sorted = sorted(self._dig_responses, key=lambda it: it.ip)
        grouped_by_ip = itertools.groupby(ip_sorted, key=lambda it: it.ip)

        for ip, ip_group in grouped_by_ip:
            host = CustomHost(ip=ip)
            host.names = [HiveLibrary.Host.Name(hostname=it.hostname, tags=[HiveLibrary.Tag(name=self._tag)]) for it in ip_group]
            hosts.append(host)

        return hosts

    def _produce_output(self) -> HiveResult:
        return HiveResult(self._build_hive_hosts())


@register_arg_helper(typ=ToolType.Dig)
class DigArgumentsHelper(ArgumentsHelper):
    @staticmethod
    def setup_args(subparsers, add_common: Callable) -> ArgumentParser:
        dig_parser: ArgumentParser = subparsers.add_parser(
            ToolType.Dig.as_str,
            help="Import dig text result in Hive project",
        )

        add_common(dig_parser)

        return dig_parser
