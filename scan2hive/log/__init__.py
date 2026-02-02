import logging
from enum import IntEnum
from logging import Logger
from pathlib import Path
from typing import ClassVar, Self


class LogLevel(IntEnum):
    NotSet = logging.NOTSET
    Debug = logging.DEBUG
    Info = logging.INFO
    Warning = logging.WARNING
    Error = logging.ERROR
    Critical = logging.CRITICAL

    @classmethod
    def from_name(cls, name: str) -> Self:
        return {
            "debug": cls.Debug,
            "info": cls.Info,
            "warning": cls.Warning,
            "error": cls.Error,
            "critical": cls.Critical,
        }.get(name, cls.NotSet)


class LoggerManager:
    __name: ClassVar[str] = "scan2hive"

    __logger: ClassVar[Logger] = None
    __init: ClassVar[bool] = False
    __formatter: ClassVar[logging.Formatter] = logging.Formatter("[%(levelname)-8s] %(asctime)s - {%(module)20s.%(funcName)-20s:%(lineno)4s}: %(message)s")

    def __new__(cls):
        raise TypeError("Static classes cannot be instantiated")

    @classmethod
    def init(cls):
        if not cls.__init:
            cls.__logger = Logger(cls.__name)
            cls.__logger.handlers = list()

            stream = logging.StreamHandler()
            stream.setFormatter(cls.__formatter)
            stream.setLevel(LogLevel.Info)

            cls.__logger.addHandler(stream)
            cls.__logger.setLevel(LogLevel.NotSet)

            cls.__init = True

    @classmethod
    def get_logger(cls) -> Logger:
        return cls.__logger

    @classmethod
    def set_root_log_level(cls, level: LogLevel):
        cls.__logger.setLevel(level)

    @classmethod
    def set_stream_log_level(cls, level: LogLevel):
        stream_handler = next(filter(lambda x: isinstance(x, logging.StreamHandler), cls.__logger.handlers))
        stream_handler.setLevel(level)

    @classmethod
    def set_log_file(cls, path: Path, level: LogLevel = LogLevel.Debug):
        """
        Set path for log file
        :param path: Path to log file
        :param level: Level for file logger
        """

        f_handlers = list(filter(lambda x: isinstance(x, logging.FileHandler), cls.__logger.handlers))
        if f_handlers and len(f_handlers) > 0:
            for it in f_handlers:
                cls.__logger.removeHandler(it)

        file_handler = logging.FileHandler(path, encoding="utf-8")
        file_handler.setFormatter(cls.__formatter)
        file_handler.setLevel(level)
        cls.__logger.addHandler(file_handler)

    @classmethod
    def set_file_log_level(cls, level: LogLevel):
        """
        Change log level for file logger.
        :param level: LogLevel: (Debug, Info, Warning, Error or Critical)
        """
        f_handler = next(filter(lambda x: isinstance(x, logging.FileHandler), cls.__logger.handlers))
        f_handler.setLevel(level)


LoggerManager.init()

__all__ = ["LoggerManager", "LogLevel"]