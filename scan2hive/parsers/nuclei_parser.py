import itertools
from argparse import ArgumentParser
from dataclasses import dataclass
from enum import IntEnum
from hive_library import HiveLibrary
from ipaddress import IPv4Address
from pathlib import Path
from typing import ClassVar, Self, Callable, List, Optional, Dict, Any

from scan2hive.hive.result import HiveResult
from scan2hive.log import LoggerManager
from scan2hive.parsers.base import ScannerFileParser, register_parser
from scan2hive.parsers.enums import ToolType
from scan2hive.parsers.helper import ArgumentsHelper, register_arg_helper
from scan2hive.parsers.mixins.json_loading_mixin import JsonLoadingMixin

logger = LoggerManager.get_logger()


class Severity(IntEnum):
    Unknown = -1
    Info = 0
    Low = 1
    Medium = 2
    High = 3
    Critical = 4

    @classmethod
    def from_name(cls, name: str) -> Self:
        return {
            "info": cls.Info,
            "low": cls.Low,
            "medium": cls.Medium,
            "high": cls.High,
            "critical": cls.Critical,
        }.get(name, cls.Unknown)

    @classmethod
    def allowed_values(cls):
        for it in filter(lambda it: it != cls.Unknown, cls):
            yield it

    @classmethod
    def allowed_values_as_names(cls):
        for it in cls.allowed_values():
            yield it.as_str.lower()

    @property
    def as_str(self) -> str:
        return self.name.upper()


@dataclass
class RawNucleiEntry:
    template_id: str
    severity: Severity
    ip: IPv4Address | None
    port: int
    description: Optional[str] = None
    extracted_results: Optional[List[str]] = None
    matched_at: Optional[str] = None
    matcher_name: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Self:
        template_id = data["template-id"]
        severity = Severity.from_name(data["info"]["severity"])
        ip = IPv4Address(data["ip"]) if ":" not in data["ip"] else None
        port = int(data["port"])
        description = data["info"].get("description", None)
        extracted_results = data.get("extracted-results", None)
        matched_at = data.get("matched-at", None)
        matcher_name = data.get("matcher-name", None)

        return cls(template_id, severity, ip, port, description, extracted_results, matched_at, matcher_name)


@dataclass
class NucleiEntry:
    extracted_results: Optional[List[str]] = None
    matcher_name: Optional[str] = None
    matched_at: Optional[str] = None

    def to_str(self) -> str:
        extracted_results = f"<i>extracted_results</i>: {', '.join(self.extracted_results)}<br>" if self.extracted_results else ""
        matcher_name = f"<i>matcher_name</i>: {self.matcher_name}<br>" if self.matcher_name else ""
        matched_at = f"<i>matched_at</i>: {self.matched_at}<br>" if self.matched_at else ""

        return extracted_results + matcher_name + matched_at


@dataclass
class NucleiEntryGroup:
    template_id: str
    entries: List[NucleiEntry]
    description: Optional[str] = None

    def to_str(self) -> str:
        hdr = f"<b>===template: {self.template_id}===</b><br>"
        description = f"<i>description</i>: {self.description}<br>" if self.description else ""
        entries = "<br>".join(map(lambda it: it.to_str(), self.entries))

        return hdr + description + entries


@dataclass
class EndpointDescriptor:
    ip: IPv4Address
    port: int
    severity: Severity
    nuclei_groups: List[NucleiEntryGroup]


@dataclass
class HiveNote:
    summary: str
    nuclei_entry_groups: List[NucleiEntryGroup]

    def to_str(self) -> str:
        summary = f"<summary>{self.summary}</summary>"
        groups = "<br>".join(map(lambda it: it.to_str(), self.nuclei_entry_groups))

        return f"<details>{summary}<br>{groups}</details>"


@register_parser
class NucleiParser(ScannerFileParser, JsonLoadingMixin):
    Type: ClassVar[ToolType] = ToolType.Nuclei

    def __init__(self, input_file: Path, tag: str, min_severity: str, ignore: List[str], *args, **kwargs):
        super().__init__(input_file, tag, *args, **kwargs)
        self._min_severity = Severity.from_name(min_severity)
        self._ignore = ignore

        self._raw_data: List[Dict[str, Any]] = None

    @staticmethod
    def _validate_json_data(json_data: List[Dict[str, Any]]) -> bool:
        try:
            template_id = json_data[0]["template-id"]
            logger.debug(f"It looks like nuclei output. First template_id is '{template_id}'.")
            return True
        except KeyError:
            logger.error(f"json is not Nuclei output.")
            return False

    def _consume_source(self):
        self._raw_data = self._load_json(self._input_file)

    def _validate_source(self):
        return self._validate_json_data(self._raw_data)

    def _parse_source(self):
        self._raw_nuclei_entries = list(
            filter(
                lambda it: it.ip is not None,
                map(
                    lambda it: RawNucleiEntry.from_dict(it),
                    self._raw_data
                )
            )
        )

    def _group_nuclei_entries(self):
        ip_sorted = sorted(self._raw_nuclei_entries, key=lambda it: it.ip)
        grouped_by_ip = itertools.groupby(ip_sorted, key=lambda it: it.ip)
        endpoint_descriptors = list()

        for ip, ip_group in grouped_by_ip:
            port_sorted = sorted(list(ip_group), key=lambda it: it.port)
            grouped_by_port = itertools.groupby(port_sorted, key=lambda it: it.port)

            for port, port_group in grouped_by_port:

                severity_sorted = sorted(port_group, key=lambda it: it.severity)
                grouped_by_severity = itertools.groupby(severity_sorted, key=lambda it: it.severity)

                for severity, severity_group in grouped_by_severity:
                    template_sorted = sorted(list(severity_group), key=lambda it: it.template_id)
                    grouped_by_template = itertools.groupby(template_sorted, key=lambda it: it.template_id)

                    nuclei_entry_groups = list()

                    for template_id, template_group in grouped_by_template:
                        template_group = list(template_group)
                        entries = [NucleiEntry(it.extracted_results, it.matcher_name, it.matched_at) for it in
                                   template_group]

                        description = template_group[0].description.strip() if template_group[0].description else ""
                        nuclei_group = NucleiEntryGroup(template_id, entries, description)
                        nuclei_entry_groups.append(nuclei_group)

                    endpoint_descriptors.append(EndpointDescriptor(ip, port, severity, nuclei_entry_groups))

        return endpoint_descriptors

    @staticmethod
    def _filter_out_ignored(nuclei_groups: List[NucleiEntryGroup], ignore: List[str]) -> List[NucleiEntryGroup]:
        if not ignore:
            return nuclei_groups

        return list(
            filter(
                lambda it: it.template_id not in ignore,
                nuclei_groups
            )
        )

    def _build_hive_hosts(self, endpoint_descriptors: List[EndpointDescriptor]) -> List[HiveLibrary.Host]:
        hosts: List[HiveLibrary.Host] = []

        ip_sorted = sorted(
            filter(
                lambda it: it.severity >= self._min_severity,
                endpoint_descriptors
            ),
            key=lambda it: it.ip
        )
        grouped_by_ip = itertools.groupby(ip_sorted, key=lambda it: it.ip)
        for ip, ip_group in grouped_by_ip:
            host = HiveLibrary.Host(ip=ip)
            host.ports = [HiveLibrary.Host.Port(
                port=it.port,
                tags=[HiveLibrary.Tag(name=self._tag)],
                notes=[HiveLibrary.Note(
                    text=HiveNote(
                        f"nuclei result. severity {it.severity.as_str}",
                        self._filter_out_ignored(it.nuclei_groups, self._ignore)
                    ).to_str()
                )]
            ) for it in ip_group]
            hosts.append(host)

        return hosts

    def _produce_output(self) -> HiveResult:
        ep_descs = self._group_nuclei_entries()
        return HiveResult(self._build_hive_hosts(ep_descs))


@register_arg_helper(typ=ToolType.Nuclei)
class NucleiArgumentsHelper(ArgumentsHelper):
    @staticmethod
    def setup_args(subparsers, add_common: Callable) -> ArgumentParser:
        nuclei_parser: ArgumentParser = subparsers.add_parser(
            ToolType.Nuclei.as_str,
            help="Import nuclei results to Hive project. You can use JSON or JSONL formatted files",
        )

        add_common(nuclei_parser)

        nuclei_parser.add_argument("-ms", "--min-severity",
                                   help="Minimum severity (default: info)",
                                   choices=list(Severity.allowed_values_as_names()),
                                   default=Severity.Info.as_str,
                                   type=str,
                                   required=False,
                                   )

        nuclei_parser.add_argument("--ignore",
                                   help="List of template IDs to ignore",
                                   nargs="*",
                                   action="extend",
                                   default=list(),
                                   required=False,
                                   )

        return nuclei_parser
