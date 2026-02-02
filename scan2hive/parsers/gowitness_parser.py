import itertools
import sqlite3
from argparse import ArgumentParser
from base64 import b64decode
from dataclasses import dataclass
from hive_library import HiveLibrary
from ipaddress import IPv4Address
from pathlib import Path
from typing import ClassVar, Self, Callable, List, Optional, Dict, Any
from urllib.parse import urlparse

from scan2hive.hive.result import GowitnessHiveResult, ScreenshotDescriptor
from scan2hive.log import LoggerManager
from scan2hive.parsers.base import ScannerFileParser, register_parser
from scan2hive.parsers.enums import ToolType, ScreenshotUploadingType
from scan2hive.parsers.helper import ArgumentsHelper, register_arg_helper

logger = LoggerManager.get_logger()


@dataclass
class RawGowitnessEntry:
    ip: IPv4Address | None  # from network_logs table
    url: str  # from result table
    response_code: int  # from result table
    screenshot: Optional[str] = None  # from result table
    title: Optional[str] = None  # from result table
    tech: Optional[List[str]] = None  # from technologies table
    server: Optional[str] = None  # from headers table
    cookie_names: Optional[List[str]] = None  # from cookies table
    final_url: Optional[str] = None  # from result table

    @classmethod
    def from_row(cls, data: sqlite3.Row) -> Self:
        # if error, no "host" in line
        ip = IPv4Address(data["remote_ip"]) if ":" not in data["remote_ip"] else None
        url = data["url"]
        response_code = int(data["response_code"])
        screenshot = data["screenshot"]
        title = data["title"] if len(data["title"]) > 0 else None
        tech = data["tech"].split(",") if data["tech"] is not None else None
        server = data["server_header"]
        cookie_names = data["cookie_names"].split(",") if data["cookie_names"] is not None else None
        final_url = data["final_url"]

        return cls(ip=ip, title=title, url=url, response_code=response_code, screenshot=screenshot,
                   tech=tech, server=server, cookie_names=cookie_names, final_url=final_url)


@dataclass
class HiveNote:
    url: str = None
    response_code: int = 0
    title: Optional[str] = None
    tech: Optional[List[str]] = None
    webserver: Optional[str] = None
    cookie_names: Optional[List[str]] = None
    final_url: Optional[str] = None

    @property
    def as_str(self) -> str:
        url = f"url: {self.url}"
        response_code = f"\nresponse_code: {self.response_code}" if self.response_code != 0 else ""
        title = f"\ntitle: {self.title}" if self.title else ""
        webserver = f"\nwebserver: {self.webserver}" if self.webserver else ""
        final_url = f"\nfinal_url: {self.final_url}" if self.final_url else ""
        tech = f"\ntech: {', '.join(self.tech)}" if self.tech else ""
        cookies = f"\ncookie_names: {', '.join(self.cookie_names)}" if self.cookie_names else ""

        return f"<b>gowitness result: <b>\n```\n{url + response_code + title + webserver + final_url + tech + cookies}\n```"


@dataclass
class EndpointDescriptor:
    ip: IPv4Address
    port: int
    hostname: Optional[str] = None
    note: HiveNote = None
    screenshot: Optional[bytes] = None


@register_parser
class GowitnessParser(ScannerFileParser):
    Type: ClassVar[ToolType] = ToolType.Gowitness
    Query: ClassVar[str] = """
                           SELECT results.url,
                                  results.title,
                                  results.final_url,
                                  results.screenshot,
                                  results.response_code,
                                  network_logs.remote_ip,
                                  headers.value                             AS server_header,
                                  GROUP_CONCAT(DISTINCT technologies.value) AS tech,
                                  GROUP_CONCAT(DISTINCT cookies.name)       AS cookie_names
                           FROM results
                                    LEFT JOIN network_logs
                                              ON results.id = network_logs.result_id and network_logs.remote_ip is not ''
                                    LEFT JOIN headers ON results.id = headers.result_id and headers.key = 'Server'
                                    LEFT JOIN technologies ON results.id = technologies.result_id
                                    LEFT JOIN cookies ON results.id = cookies.result_id
                           GROUP BY results.id \
                           """

    def __init__(self, input_file: Path, tag: str, upload_screenshots: str, *args, **kwargs):
        super().__init__(input_file, tag, *args, **kwargs)
        self._upload_screenshots: ScreenshotUploadingType = ScreenshotUploadingType.from_name(upload_screenshots)
        self._raw_data: List[Dict[str, Any]] = None
        self._raw_gowitness_entries: List[RawGowitnessEntry] = None

    def _consume_source(self):
        try:
            con = sqlite3.connect(self._input_file)
            con.row_factory = sqlite3.Row
            cur = con.cursor()
        except:
            logger.error(f"Cannot connect to database '{self._input_file}'")
        try:
            cur.execute(self.Query)
            self._raw_data = cur.fetchall()
        except:
            logger.error(f"Cannot read gowitness results from database '{self._input_file}'")
        con.close()

    def _validate_source(self):
        if not self._raw_data:
            return False
        return True

    def _parse_source(self):
        self._raw_gowitness_entries = list(
            filter(
                lambda it: it.ip is not None,
                map(
                    lambda it: RawGowitnessEntry.from_row(it),
                    self._raw_data
                )
            )
        )

    def _build_endpoint_descriptors(self):
        endpoint_descriptors: list[EndpointDescriptor] = list()
        for it in self._raw_gowitness_entries:
            note = HiveNote(url=it.url, response_code=it.response_code, title=it.title, tech=it.tech,
                            webserver=it.server, cookie_names=it.cookie_names, final_url=it.final_url)
            hostname = urlparse(it.url).hostname
            port = urlparse(it.url).port if urlparse(it.url).port is not None else 443 if urlparse(
                it.url).scheme == "https" else 80
            screenshot = b64decode(it.screenshot)
            endpoint_descriptors.append(EndpointDescriptor(ip=it.ip, port=port, hostname=hostname,
                                                           note=note, screenshot=screenshot))

        return endpoint_descriptors

    def _build_hive_hosts(self, endpoint_descriptors: List[EndpointDescriptor]) -> List[HiveLibrary.Host]:
        hosts: List[HiveLibrary.Host] = list()
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
                                                notes=[HiveLibrary.Note(text=it.note.as_str)]) for it in ip_group]
            hosts.append(host)
        return hosts

    def _build_screenshot_descriptors(self, endpoint_descriptors: List[EndpointDescriptor]) -> List[ScreenshotDescriptor] | None:
        if self._upload_screenshots == ScreenshotUploadingType.NO:
            logger.info("Do not add screenshots")
            return None
        screenshot_descriptors: List[ScreenshotDescriptor] = list()
        if self._upload_screenshots == ScreenshotUploadingType.ALL:
            logger.info("Add all screenshots")
            for it in endpoint_descriptors:
                screenshot_descriptors.append(ScreenshotDescriptor(ip=it.ip, port=it.port, screenshot_data=it.screenshot))
        elif self._upload_screenshots == ScreenshotUploadingType.OK:
            logger.info("Add screenshots for status code 200 Ok")
            for it in filter(lambda it: it.note.response_code == 200, endpoint_descriptors):
                screenshot_descriptors.append(ScreenshotDescriptor(ip=it.ip, port=it.port, screenshot_data=it.screenshot))
        return screenshot_descriptors

    def _produce_output(self) -> GowitnessHiveResult:
        ep_descs = self._build_endpoint_descriptors()
        hosts = self._build_hive_hosts(ep_descs)
        screen_descs = self._build_screenshot_descriptors(ep_descs)
        return GowitnessHiveResult(hosts=hosts, screendhot_descriptors=screen_descs)


@register_arg_helper(typ=ToolType.Gowitness)
class GowitnessArgumentsHelper(ArgumentsHelper):
    @staticmethod
    def setup_args(subparsers, add_common: Callable) -> ArgumentParser:
        gowitness_parser: ArgumentParser = subparsers.add_parser(
            ToolType.Gowitness.as_str,
            help="Import gowitness result to Hive project. Input is sqlite file",
        )

        add_common(gowitness_parser)

        gowitness_parser.add_argument("-us", "--upload-screenshots",
                                      help=f"upload screenshots (not upload by default) (default: {ScreenshotUploadingType.NO.value})",
                                      choices=list(ScreenshotUploadingType.allowed_values()),
                                      required=False,
                                      type=str,
                                      default=ScreenshotUploadingType.NO.value)
        return gowitness_parser
