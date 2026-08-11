import itertools
from argparse import ArgumentParser
from dataclasses import dataclass
from ipaddress import IPv4Address
from pathlib import Path
from typing import ClassVar, Self, Callable, List, Optional, Dict, Any
from urllib.parse import urlparse

from hive_library import HiveLibrary

from scan2hive.hive.custom_rest_api import CustomHost
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
    subject_cn: Optional[str] = None
    subject_an: Optional[List[str]] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Self:
        # if error, no "host" in line
        ip = None
        host_ip = data.get("host_ip", None)
        # old schema. get ip from host field
        if host_ip is None:
            host_ip = data.get("host") if data.get("host") else None
        # modern httpx schema. get ip from resolved addresses
        if host_ip is None:
            host_ip = data.get("a")[0] if data.get("a") else None
        if host_ip:
            ip = IPv4Address(host_ip) if ":" not in host_ip else None
        port = int(data.get("port", "0"))
        url = data["url"]
        title = data.get("title", None)
        webserver = data.get("webserver", None)
        tech = data.get("tech", None)
        final_url = data.get("final_url", None)
        tls = data.get("tls", None)
        subject_cn = tls.get("subject_cn", None) if tls is not None else None
        subject_an = tls.get("subject_an", None) if tls is not None else None

        return cls(ip=ip, port=port, title=title, webserver=webserver, url=url, tech=tech,
                   final_url=final_url, subject_cn=subject_cn, subject_an=subject_an)

@dataclass
class HiveNote:
    url: str = None
    title: Optional[str] = None
    webserver: Optional[str] = None
    tech: Optional[List[str]] = None
    final_url: Optional[str] = None
    subject_cn: Optional[str] = None
    subject_an: Optional[List[str]] = None

    def to_str(self) -> str:
        url = f"url: {self.url}"
        title = f"\ntitle: {self.title}" if self.title else ""
        webserver = f"\nwebserver: {self.webserver}" if self.webserver else ""
        final_url = f"\nfinal_url: {self.final_url}" if self.final_url else ""
        tech = f"\ntech: {', '.join(self.tech)}" if self.tech else ""
        subject_cn = f"\nsubject_cn: {self.subject_cn}" if self.subject_cn else ""
        subject_an = f"\nsubject_an: {', '.join(self.subject_an)}" if self.subject_an and self.subject_an != [self.subject_cn] else ""

        return f"<b>httpx result:<b>\n```\n{url + title + webserver + final_url + tech + subject_cn + subject_an}\n```"


@dataclass
class EndpointDescriptor:
    ip: IPv4Address
    port: int
    hostname: Optional[str] = None
    note: HiveNote = None


@register_parser
class HttpxParser(ScannerFileParser, JsonLoadingMixin):
    Type: ClassVar[ToolType] = ToolType.HttpX

    def __init__(self, input_file: Path, tag: str, max_hostnames: int, *args, **kwargs):
        super().__init__(input_file, tag, *args, **kwargs)

        self._raw_data: List[Dict[str, Any]] = None
        self._raw_httpx_entries: List[RawHttpxEntry] = None
        self._max_hostnames = max_hostnames

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
            note = HiveNote(title=it.title, webserver=it.webserver, url=it.url, tech=it.tech, final_url=it.final_url,
                            subject_cn=it.subject_cn, subject_an=it.subject_an)
            hostname = urlparse(it.url).hostname
            endpoint_descriptors.append(EndpointDescriptor(ip=it.ip, port=it.port, hostname=hostname, note=note))

        return endpoint_descriptors

    def _build_hive_hosts(self, endpoint_descriptors: List[EndpointDescriptor]) -> HiveResult:
        hosts: List[CustomHost] = []

        ip_sorted = sorted(endpoint_descriptors, key=lambda it: it.ip)
        grouped_by_ip = itertools.groupby(ip_sorted, key=lambda it: it.ip)
        for ip, ip_group in grouped_by_ip:
            host = CustomHost(ip=ip)
            ip_group = list(ip_group)
            host.names = [HiveLibrary.Host.Name(hostname=it.hostname) for it in
                          filter(
                              lambda it: it.hostname is not None and it.hostname != str(it.ip),
                              ip_group
                          )]
            if len(host.names) > self._max_hostnames:
                host.notes.append(HiveLibrary.Note(text=f"{len(host.names)} hostnames. No hostnames and notes will be imported, see https result"))
                logger.info(f"Host {host.ip} has {len(host.names)} hostnames. Skip notes.")
                host.names = []
            else:
                port_sorted = sorted(ip_group, key=lambda it: it.port)
                grouped_by_port = itertools.groupby(port_sorted, key=lambda it: it.port)

                for port, port_group in grouped_by_port:
                    port_group=list(port_group)
                    host.ports.append(HiveLibrary.Host.Port(port=port, tags=[HiveLibrary.Tag(name=self._tag)],
                                                notes=[HiveLibrary.Note(text=it.note.to_str()) for it in port_group]))
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

        httpx_parser.add_argument("-m", "--max-hostnames",
                                 help="Max number of hostnames. Default is 10",
                                 required=False,
                                 default=10,
                                 type=int)

        return httpx_parser
