from enum import IntEnum, auto, Enum
from typing import Self


class ToolType(IntEnum):
    Unknown = -1
    Nmap = auto()
    Nuclei = auto()
    HttpX = auto()
    Gowitness = auto()
    Poseidon = auto()
    Dig = auto()
    Dnsx = auto()

    @classmethod
    def from_name(cls, name: str) -> Self:
        return {
            "nmap": ToolType.Nmap,
            "nuclei": ToolType.Nuclei,
            "httpx": ToolType.HttpX,
            "gowitness": ToolType.Gowitness,
            "poseidon": ToolType.Poseidon,
            "dig": ToolType.Dig,
            "dnsx": ToolType.Dnsx,
        }.get(name, cls.Unknown)

    @property
    def as_str(self) -> str:
        return self.name.lower()


class WorkMode(IntEnum):
    Unknown = -1
    DryRun = auto()
    Upload = auto()


class ScriptParsingType(Enum):
    as_record = "record"
    as_note = "note"
    not_parse = "not_parse"

    @classmethod
    def from_name(cls, name: str) -> Self:
        return {
            "record": cls.as_record,
            "note": cls.as_note,
            "not_parse": cls.not_parse,
        }.get(name, cls.not_parse)

    @classmethod
    def allowed_values(cls):
        return [it.value for it in cls]


class ScreenshotUploadingType(Enum):
    NO = "no"
    ALL = "all"
    OK = "only_200ok"

    @classmethod
    def from_name(cls, name: str) -> Self:
        return {
            "no": ScreenshotUploadingType.NO,
            "all": ScreenshotUploadingType.ALL,
            "only_200ok": ScreenshotUploadingType.OK,
        }.get(name, cls.NO)

    @classmethod
    def allowed_values(cls):
        return [it.value for it in cls]


class InputType(IntEnum):
    Unknown = -1
    File = auto()
    Database = auto()
    

class DnsRecordType(Enum):
    A = "A"
    AAAA = "AAAA"
    CNAME = "CNAME"
    MX = "MX"
    TXT = "TXT"
    NS = "NS"

    @classmethod
    def allowed_values(cls):
        return [it.value for it in cls]
