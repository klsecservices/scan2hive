import itertools
from argparse import ArgumentParser
from dataclasses import dataclass
from hive_library import HiveLibrary
from ipaddress import IPv4Address
from pathlib import Path
from typing import ClassVar, Self, Callable, List, Optional, Dict, Any, Set

from scan2hive.hive.result import HiveResult
from scan2hive.log import LoggerManager
from scan2hive.parsers.base import ScannerFileParser, register_parser
from scan2hive.parsers.enums import ToolType
from scan2hive.parsers.helper import ArgumentsHelper, register_arg_helper
from scan2hive.parsers.mixins.json_loading_mixin import JsonLoadingMixin

logger = LoggerManager.get_logger()


@dataclass
class PortscanEntry:
    ip: IPv4Address | None
    ports: Set[int]
    hostnames: Optional[Set[str]] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Self:
        ip = IPv4Address(data["ip"]) if ":" not in data["ip"] else None
        hostnames = {data["hostname"]} if data["hostname"] is not "" else {}
        ports = data["open_ports"]

        return cls(ip=ip, ports=ports, hostnames=hostnames)


@register_parser
class PoseidonParser(ScannerFileParser, JsonLoadingMixin):
    Type: ClassVar[ToolType] = ToolType.Poseidon

    def __init__(self, input_file: Path, tag: str, *args, **kwargs):
        super().__init__(input_file, tag, *args, **kwargs)

        self._raw_scan_entries: List[PortscanEntry] = None

    @staticmethod
    def _validate_json_data(json_data: List[Dict[str, Any]]) -> bool:
        try:
            first_range = json_data[0]["range"]
            ip = json_data[0]["hosts"][0]["ip"]
            logger.debug(f"It looks like poseidon portscan output. First range is '{first_range}', first IP is '{ip}'.")
            return True
        except KeyError:
            logger.error(f"json is not Poseidon portscan output.")
            return False

    def _consume_source(self):
        self._raw_data = self._load_json(self._input_file)

    def _validate_source(self):
        return self._validate_json_data(self._raw_data)

    def _parse_source(self):
        self._raw_scan_entries = list()
        for ip_range in self._raw_data:
            self._raw_scan_entries.extend(
                list(
                    filter(
                        lambda it: it.ip is not None,
                        map(
                            lambda it: PortscanEntry.from_dict(it),
                            ip_range["hosts"]
                        )
                    )
                )
            )

    def _group_portscan_entries(self) -> List[PortscanEntry]:
        ip_sorted = sorted(self._raw_scan_entries, key=lambda it: it.ip)
        grouped_by_ip = itertools.groupby(ip_sorted, key=lambda it: it.ip)

        grouped_portscan_entries: List[PortscanEntry] = list()

        for ip, ip_group in grouped_by_ip:
            hosts = list(ip_group)
            hostnames = set(itertools.chain.from_iterable(it.hostnames for it in hosts))
            ports = set(itertools.chain.from_iterable(it.ports for it in hosts))
            grouped_portscan_entries.append(PortscanEntry(ip=ip, ports=ports, hostnames=hostnames))

        return grouped_portscan_entries

    def _build_hive_hosts(self, portscan_entries: List[PortscanEntry]) -> List[HiveLibrary.Host]:
        hosts: List[HiveLibrary.Host] = []
        for it in portscan_entries:
            host = HiveLibrary.Host(ip=it.ip)
            host.ports = [HiveLibrary.Host.Port(port=port, tags=[HiveLibrary.Tag(name=self._tag)]) for port in it.ports]
            host.names = [HiveLibrary.Host.Name(hostname=name) for name in it.hostnames]
            hosts.append(host)

        return hosts

    def _produce_output(self) -> HiveResult:
        grouped_entries = self._group_portscan_entries()
        return HiveResult(self._build_hive_hosts(grouped_entries))


@register_arg_helper(typ=ToolType.Poseidon)
class HttpxArgumentsHelper(ArgumentsHelper):
    @staticmethod
    def setup_args(subparsers, add_common: Callable) -> ArgumentParser:
        poseidon_parser: ArgumentParser = subparsers.add_parser(
            ToolType.Poseidon.as_str,
            help="Import poseidon portscan json result in Hive project",
        )

        add_common(poseidon_parser)

        return poseidon_parser
