from abc import ABCMeta, abstractmethod
from argparse import ArgumentParser
from typing import ClassVar, Dict, Type, Any, Generator, Callable

from scan2hive.log import LoggerManager
from scan2hive.parsers.enums import ToolType

logger = LoggerManager.get_logger()


class ArgumentsHelper(metaclass=ABCMeta):
    @staticmethod
    @abstractmethod
    def setup_args(subparsers, add_common: Callable) -> ArgumentParser:
        ...


class ArgumentsHelperFactory:
    _items: ClassVar[Dict[ToolType, Type[ArgumentsHelper]]] = {}

    @classmethod
    def register(cls, typ: ToolType, klass: Type[ArgumentsHelper]):
        if typ not in cls._items:
            cls._items[typ] = klass
            logger.debug(f"Registered '{klass.__name__}' for type '{typ.name}'")
        else:
            msg = f"ArgumentsHelper class '{klass.__name__}' with type '{typ.name}' is already registered"
            logger.error(msg)
            raise KeyError(msg)

    @classmethod
    def get(cls, typ: ToolType) -> Type[ArgumentsHelper]:
        if typ not in cls._items:
            msg = f"No ArgumentsHelper class registered for type '{typ.name}'"
            logger.error(msg)
            raise KeyError(msg)
        else:
            return cls._items[typ]

    @classmethod
    def iterate(cls) -> Generator[Type[ArgumentsHelper], Any, None]:
        for typ in cls._items:
            yield cls._items[typ]


def register_arg_helper(cls=None, /, *, typ: ToolType = ToolType.Unknown):
    def wrap(cls):
        if typ == ToolType.Unknown:
            msg = f"Invalid type: '{typ.name}' for class '{cls.__name__}'"
            logger.error(msg)
            raise ValueError(msg)

        ArgumentsHelperFactory.register(typ, cls)
        return cls

    if cls is None:
        return wrap

    return wrap(cls)


def register_sub_commands(subparsers, common_stage_1: Callable, common_stage_2: Callable):
    parsers = []

    for it in ArgumentsHelperFactory.iterate():
        p = it.setup_args(subparsers, common_stage_1)
        parsers.append(p)

    for it in parsers:
        common_stage_2(it)
