from abc import ABCMeta, abstractmethod, ABC
from pathlib import Path
from typing import ClassVar, Dict, Type

from scan2hive.hive.result import HiveResult
from scan2hive.log import LoggerManager
from scan2hive.parsers.enums import ToolType

logger = LoggerManager.get_logger()


class ScannerParser(metaclass=ABCMeta):
    Type: ClassVar[ToolType] = ToolType.Unknown

    def __init__(self, *args, **kwargs):
        ...

    def handle_source(self) -> HiveResult | None:
        self._consume_source()
        if not self._validate_source():
            exit(1)

        self._parse_source()
        return self._produce_output()

    @abstractmethod
    def _consume_source(self):
        ...

    @abstractmethod
    def _validate_source(self):
        ...

    @abstractmethod
    def _parse_source(self):
        ...

    @abstractmethod
    def _produce_output(self) -> HiveResult:
        ...


class ScannerFileParser(ScannerParser, metaclass=ABCMeta):
    Type: ClassVar[ToolType] = ToolType.Unknown

    def __init__(self, input_file: Path, tag: str, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if not input_file.exists():
            msg = f"File '{input_file}' does not exist"
            logger.error(msg)
            raise FileNotFoundError(msg)

        self._input_file = input_file
        self._tag = tag


class ScannerParserFactory:
    _items: ClassVar[Dict[ToolType, Type[ScannerParser]]] = {}

    @classmethod
    def register(cls, typ: ToolType, klass: Type[ScannerParser]):
        if typ not in cls._items:
            cls._items[typ] = klass
            logger.debug(f"Registered '{klass.__name__}' for type '{typ.name}'")
        else:
            msg = f"ScannerParser class '{klass.__name__}' with type '{typ.name}' is already registered"
            logger.error(msg)
            raise KeyError(msg)

    @classmethod
    def get(cls, typ: ToolType) -> Type[ScannerParser]:
        if typ not in cls._items:
            msg = f"No ScannerParser class registered for type '{typ.name}'"
            logger.error(msg)
            raise KeyError(msg)
        else:
            return cls._items[typ]


def register_parser(cls=None, /):
    def wrap(cls):
        ScannerParserFactory.register(cls.Type, cls)
        return cls

    if cls is None:
        return wrap

    return wrap(cls)
