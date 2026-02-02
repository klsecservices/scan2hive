import itertools
from argparse import ArgumentParser
from dataclasses import dataclass
from hive_library import HiveLibrary
from ipaddress import IPv4Address
from pathlib import Path
from typing import ClassVar, Self, Callable, List, Optional, Dict, Any
from urllib.parse import urlparse

from scan2hive.hive.result import HiveResult
from scan2hive.log import LoggerManager
from scan2hive.parsers.base import ScannerFileParser, register_parser
from scan2hive.parsers.enums import ToolType
from scan2hive.parsers.helper import ArgumentsHelper, register_arg_helper
from scan2hive.parsers.mixins.json_loading_mixin import JsonLoadingMixin

logger = LoggerManager.get_logger()


@dataclass
class RawHttpxEntry:
    ip: IPv4Address | None
    port: int
    url: str
    title: Optional[str] = None
    webserver: Optional[str] = None
    tech: Optional[List[str]] = None
    final_url: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Self:
        # if error, no "host" in line
        ip = None
        host = data.get("host", None)
        # modern httpx schema. get ip from resolved addresses
        if host is None:
            host = data.get("a")[0] if data.get("a") else None
        if host:
            ip = IPv4Address(host) if ":" not in host else None
        port = int(data.get("port", "0"))
        url = data["url"]
        title = data.get("title", None)
        webserver = data.get("webserver", None)
        tech = data.get("tech", None)
        final_url = data.get("final_url", None)

        return cls(ip=ip, port=port, title=title, webserver=webserver, url=url, tech=tech, final_url=final_url)


@dataclass
class HiveNote:
    url: str = None
    title: Optional[str] = None
    webserver: Optional[str] = None
    tech: Optional[List[str]] = None
    final_url: Optional[str] = None

    def to_str(self) -> str:
        url = f"url: {self.url}"
        title = f"\ntitle: {self.title}" if self.title else ""
        webserver = f"\nwebserver: {self.webserver}" if self.webserver else ""
        final_url = f"\nfinal_url: {self.final_url}" if self.final_url else ""
        tech = f"\ntech: {', '.join(self.tech)}" if self.tech else ""

        return f"<b>httpx result:<b>\n```\n{url + title + webserver + final_url + tech}\n```"


@dataclass
class EndpointDescriptor:
    ip: IPv4Address
    port: int
    hostname: Optional[str] = None
    note: HiveNote = None


@register_parser
class HttpxParser(ScannerFileParser, JsonLoadingMixin):
    Type: ClassVar[ToolType] = ToolType.HttpX

    def __init__(self, input_file: Path, tag: str, *args, **kwargs):
        super().__init__(input_file, tag, *args, **kwargs)

        self._raw_data: List[Dict[str, Any]] = None
        self._raw_httpx_entries: List[RawHttpxEntry] = None

    @staticmethod
    def _validate_json_data(json_data: List[Dict[str, Any]]) -> bool:
        try:
            url = json_data[0]["url"]
            input = json_data[0]["input"]
            logger.debug(f"It looks like httpx output. First url is '{url}' for input '{input}'.")
            return True
        except KeyError:
            logger.error(f"json is not httpx output.")
            return False

    def _consume_source(self):
        self._raw_data = self._load_json(self._input_file)

    def _validate_source(self):
        return self._validate_json_data(self._raw_data)

    def _parse_source(self):
        self._raw_httpx_entries = list(
            filter(
                lambda it: it.ip is not None,
                map(
                    lambda it: RawHttpxEntry.from_dict(it),
                    self._raw_data
                )
            )
        )

    def _build_endpoint_descriptors(self):
        endpoint_descriptors: list[EndpointDescriptor] = list()
        for it in self._raw_httpx_entries:
            note = HiveNote(title=it.title, webserver=it.webserver, url=it.url, tech=it.tech, final_url=it.final_url)
            hostname = urlparse(it.url).hostname
            endpoint_descriptors.append(EndpointDescriptor(ip=it.ip, port=it.port, hostname=hostname, note=note))

        return endpoint_descriptors

    def _build_hive_hosts(self, endpoint_descriptors: List[EndpointDescriptor]) -> HiveResult:
        hosts: List[HiveLibrary.Host] = []

        ip_sorted = sorted(endpoint_descriptors, key=lambda it: it.ip)
        grouped_by_ip = itertools.groupby(ip_sorted, key=lambda it: it.ip)
        for ip, ip_group in grouped_by_ip:
            host = HiveLibrary.Host(ip=ip)
            ip_group = list(ip_group)
            host.names = [HiveLibrary.Host.Name(hostname=it.hostname) for it in
                          filter(
                              lambda it: it.hostname is not None and it.hostname != str(it.ip),
                              ip_group
                          )]
            host.ports = [HiveLibrary.Host.Port(port=it.port, tags=[HiveLibrary.Tag(name=self._tag)],
                                                notes=[HiveLibrary.Note(text=it.note.to_str())]) for it in ip_group]
            hosts.append(host)
        return HiveResult(hosts)

    def _produce_output(self) -> HiveResult:
        ep_descs = self._build_endpoint_descriptors()
        return self._build_hive_hosts(ep_descs)


@register_arg_helper(typ=ToolType.HttpX)
class HttpxArgumentsHelper(ArgumentsHelper):
    @staticmethod
    def setup_args(subparsers, add_common: Callable) -> ArgumentParser:
        httpx_parser: ArgumentParser = subparsers.add_parser(
            ToolType.HttpX.as_str,
            help="Import httpx json result in Hive project",
        )

        add_common(httpx_parser)

        return httpx_parser
