import itertools
from argparse import ArgumentParser
from bs4 import BeautifulSoup, element
from dataclasses import dataclass
from hive_library import HiveLibrary
from hive_library.enum import RecordTypes
from ipaddress import IPv4Address
from pathlib import Path
from time import time
from typing import ClassVar, Self, Callable, List, Optional, Set, Dict, Any

from scan2hive.hive.result import HiveResult
from scan2hive.log import LoggerManager
from scan2hive.parsers.base import ScannerFileParser, register_parser
from scan2hive.parsers.enums import ScriptParsingType
from scan2hive.parsers.enums import ToolType
from scan2hive.parsers.helper import ArgumentsHelper, register_arg_helper
from scan2hive.parsers.mixins.xml_loading_mixin import XMLLoadingMixin

logger = LoggerManager.get_logger()


@dataclass
class ScriptElement:
    key: Optional[str] = None
    text: Optional[str] = None

    @classmethod
    def from_tag(cls, tag: element.Tag) -> Self:
        key = tag.get("key")
        text = tag.text.strip() if tag.name == "elem" and tag.text else None
        return cls(key=key, text=text)

    def to_str(self):
        return f"{self.key.strip()}: {self.text}\n" if self.key else f"{self.text}\n"


@dataclass
class ScriptInfo:
    id: Optional[str] = None
    key: Optional[str] = None
    output: Optional[str] = None
    tables: Optional[List["ScriptInfo"]] = None
    elements: Optional[List[ScriptElement]] = None

    @classmethod
    def from_tag(cls, tag: element.Tag) -> Self:
        script_id = tag.get("id", None)
        key = tag.get("key", None)
        output = tag.get("output", None)
        elements = [ScriptElement.from_tag(child) for child in
                    tag.find_all("elem", recursive=False)] if tag.find_all("elem") is not None else []
        tables = [ScriptInfo.from_tag(child) for child in
                  tag.find_all("table", recursive=False)] if tag.find_all("table") is not None else []
        return cls(id=script_id, key=key, output=output, elements=elements, tables=tables)

    def to_note(self) -> str:
        note_text = "<details>\n"
        header = self.id if self.id else self.key
        if header:
            note_text += f"<summary>{header.strip()}</summary>\n"
        if self.output:
            note_text += f"{self.output.strip()}\n"

        for table in self.tables:
            note_text += table.to_note()
        for elem in self.elements:
            note_text += elem.to_str()
        note_text += "</details>\n"

        return note_text.strip()

    def to_hive_record(self) -> HiveLibrary.Record:
        record: HiveLibrary.Record = HiveLibrary.Record(tool_name="nmap")
        record.name = self.id if self.id else self.key if self.key else f"Details ({time()})"
        if len(self.tables) > 0:
            record.record_type = RecordTypes.NESTED.value
            record.extra = self.output
            for table in self.tables:
                record.value.append(table.to_hive_record())
        elif len(self.elements) > 0:
            if len(self.elements) > 1:
                record.record_type = RecordTypes.LIST.value
                for elem in self.elements:
                    record.value.append(elem.to_str())
            else:
                record.record_type = RecordTypes.STRING.value
                record.value = self.elements[0].to_str()
                record.extra = self.output

        else:
            record.record_type = RecordTypes.STRING.value
            record.value = self.output

        return record


@dataclass
class ServiceInfo:
    name: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None

    @classmethod
    def from_tag(cls, element: element.Tag) -> Self:
        name = element.get("name", None)
        product = element.get("product", None)
        version = element.get("version", None)
        return cls(name=name, product=product, version=version)

    def to_hive_service(self) -> HiveLibrary.Host.Port.Service:
        service = HiveLibrary.Host.Port.Service()
        service.name = self.name
        service.product = self.product
        service.version = self.version
        return service


@dataclass
class PortInfo:
    number: int
    protocol: str
    state: str
    service: Optional[ServiceInfo] = None
    scripts: Optional[List[ScriptInfo]] = None

    @classmethod
    def from_tag(cls, element: element.Tag) -> Self:
        number = int(element.get('portid'))
        protocol = element.get('protocol')
        state_tag: element.Tag = element.find('state')
        state = state_tag.get('state', 'unknown') if state_tag is not None else 'unknown'
        service = ServiceInfo.from_tag(element.find('service')) if element.find('service') is not None else None

        scripts = [ScriptInfo.from_tag(tag) for tag in
                   element.find_all('script', recursive=False)] if element.find_all('script', recursive=False) is not None else []

        return cls(number=number, protocol=protocol, state=state, service=service, scripts=scripts)

    def to_hive_port(self, tag: str, script_parser_type: ScriptParsingType) -> HiveLibrary.Host.Port:
        port: HiveLibrary.Host.Port = HiveLibrary.Host.Port()
        port.port = self.number
        port.protocol = self.protocol
        port.state = self.state
        port.tags.append(HiveLibrary.Tag(name=tag))
        port.service = self.service.to_hive_service() if self.service is not None else None
        if script_parser_type == ScriptParsingType.as_record:
            port.records = list()
            for script in self.scripts:
                port.records.append(script.to_hive_record())
        elif script_parser_type == ScriptParsingType.as_note:
            port.notes = list()
            for script in self.scripts:
                port.notes.append(HiveLibrary.Note(text=script.to_note()))

        return port


@dataclass
class ScanEntry:
    ip: IPv4Address | None
    hostnames: Optional[List[str]] = None
    ports: Optional[List[PortInfo]] = None
    scripts: Optional[List[ScriptInfo]] = None

    @classmethod
    def from_tag(cls, elem: element.Tag) -> Self:
        addr: str = elem.find('address').get('addr')
        ip = IPv4Address(addr) if ":" not in addr else None
        hostnames_tag = elem.find("hostnames")
        hostnames = []
        if hostnames_tag is not None:
            hostnames = [hostname.get("name") for hostname in
                         hostnames_tag.find_all("hostname")] if hostnames_tag.find_all("hostname") else []
        scripts = [ScriptInfo.from_tag(tag) for tag
                   in elem.find_all('script', recursive=False)] if elem.find_all('script', recursive=False) is not None else []
        ports_tag = elem.find("ports")
        ports = [PortInfo.from_tag(port_tag) for port_tag in
                 ports_tag.find_all("port", recursive=False)] if ports_tag else []

        return cls(ip=ip, hostnames=hostnames, ports=ports, scripts=scripts)

    def to_hive_host(self, tag: str, script_parser_type: ScriptParsingType) -> HiveLibrary.Host:
        def _get_hostnames_from_scripts(host: ScanEntry) -> List[HiveLibrary.Host.Name]:
            scripts_with_hostnames = ["ssl-cert"]
            hostnames: List[HiveLibrary.Host.Name] = list()
            for script in host.scripts:
                if script.id not in scripts_with_hostnames:
                    continue
            for port in host.ports:
                for script in port.scripts:
                    if script.id not in scripts_with_hostnames:
                        continue
                    if script.id == "ssl-cert":
                        subject_table = next(filter(lambda table: table.key == "subject", script.tables))
                        hostnames.append(HiveLibrary.Host.Name(hostname=subject_table.elements[0].text,
                                                               tags=[HiveLibrary.Tag(name="from script ssl-cert")]))
            return hostnames

        host = HiveLibrary.Host(ip=self.ip)
        for hostname in set(self.hostnames):
            host.names.append(HiveLibrary.Host.Name(hostname=hostname))
        for hostname in _get_hostnames_from_scripts(self):
            host.names.append(hostname)
        for port in self.ports:
            host.ports.append(port.to_hive_port(tag=tag, script_parser_type=script_parser_type))

        if script_parser_type == ScriptParsingType.as_record:
            host.records = list()
            for script in self.scripts:
                host.records.append(script.to_hive_record())
        elif script_parser_type == ScriptParsingType.as_note:
            host.notes = list()
            for script in self.scripts:
                host.notes.append(HiveLibrary.Note(text=script.to_note()))
        return host


@register_parser
class NmapParser(ScannerFileParser, XMLLoadingMixin):
    Type: ClassVar[ToolType] = ToolType.Nmap

    def __init__(self, input_file: Path, tag: str, script_parsing: str, max_ports: int, *args, **kwargs):
        super().__init__(input_file, tag, *args, **kwargs)
        self._script_parsing_type: ScriptParsingType = ScriptParsingType.from_name(script_parsing)
        self._max_ports: int = max_ports

        self._raw_data: element.Tag
        self._raw_scan_entries: List[ScanEntry] = None

    @staticmethod
    def _validate_xml_data(root: element.Tag) -> bool:
        try:
            scanner_name = root.get('scanner')
            if scanner_name not in ["nmap", "masscan"]:
                logger.error(f"Cannot parse '{scanner_name}' result")
                return False
            return True
        except:
            logger.error(f"Cannot get scanner name. Input file is not nmap or masscan result?")
            return False

    def _consume_source(self):
        self._raw_data = self._load_xml(self._input_file, "nmaprun")

    def _validate_source(self):
        return self._validate_xml_data(self._raw_data)

    def _parse_source(self):
        self._raw_scan_entries = list(
            filter(
                lambda it: it.ip is not None,
                map(
                    lambda it: ScanEntry.from_tag(it),
                    self._raw_data.find_all('host')
                )
            )
        )

    def _group_raw_scan_entry(self) -> List[ScanEntry]:

        ip_sorted = sorted(self._raw_scan_entries, key=lambda it: it.ip)
        grouped_by_ip = itertools.groupby(ip_sorted, key=lambda it: it.ip)
        grouped_scan_entries: List[ScanEntry] = list()

        for ip, ip_group in grouped_by_ip:
            ip_group = list(ip_group)
            host = ScanEntry(ip=ip, hostnames=list(), ports=list(), scripts=list())
            for scan_entry in ip_group:
                host.hostnames.extend(scan_entry.hostnames)
                host.ports.extend(scan_entry.ports)
                host.scripts.extend(scan_entry.scripts)
            grouped_scan_entries.append(host)

        return grouped_scan_entries

    @staticmethod
    def _filter_bad_ports(entries: List[ScanEntry], accepted_protocols: List[str] = ["tcp", "udp"],
                          min_port_number: int = 1, max_port_number: int = 65535) -> List[ScanEntry]:
        filtered_entries: List[ScanEntry] = list()
        for entry in entries:
            host = entry
            ports = list(
                filter(
                    lambda it: it.protocol in accepted_protocols and min_port_number <= it.number <= max_port_number,
                    host.ports
                ))
            host.ports = ports
            filtered_entries.append(host)
        return filtered_entries

    def _build_hive_hosts(self, entries: List[ScanEntry]) -> List[HiveLibrary.Host]:
        hosts: List[HiveLibrary.Host] = list()
        for it in entries:
            host = it.to_hive_host(script_parser_type=self._script_parsing_type, tag=self._tag)
            if len(host.ports) > self._max_ports:
                host.notes.append(HiveLibrary.Note(text=f"{len(host.ports)} ports. No port will be imported"))
                logger.info(f"Host {host.ip} has {len(host.ports)} open ports. Skip ports.")
                host.ports = list()
            hosts.append(host)
        return hosts

    def _produce_output(self) -> HiveResult:
        grouped_scan_entries = self._group_raw_scan_entry()
        filtered_entries = self._filter_bad_ports(grouped_scan_entries)
        return HiveResult(self._build_hive_hosts(filtered_entries))


@register_arg_helper(typ=ToolType.Nmap)
class HttpxArgumentsHelper(ArgumentsHelper):
    @staticmethod
    def setup_args(subparsers, add_common: Callable) -> ArgumentParser:
        nmap_parser: ArgumentParser = subparsers.add_parser(
            ToolType.Nmap.as_str,
            help="Import nmap or masscan result (XML format) to Hive project",
        )

        add_common(nmap_parser)

        nmap_parser.add_argument("-m", "--max-ports",
                                 help="Max number of ports. Default is 300",
                                 required=False,
                                 default=300,
                                 type=int)

        nmap_parser.add_argument("--script-parsing",
                                 help=f"How to parse scripts. Default is {ScriptParsingType.as_record.value}",
                                 choices=list(ScriptParsingType.allowed_values()),
                                 required=False,
                                 type=str,
                                 default=ScriptParsingType.as_record.value)

        return nmap_parser
