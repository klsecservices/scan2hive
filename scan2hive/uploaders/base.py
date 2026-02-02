import itertools
from abc import ABCMeta
from getpass import getpass
from hive_library import HiveLibrary
from typing import ClassVar, Dict, Type, Iterable

from scan2hive.hive.custom_rest_api import CustomHiveRestApi as HiveRestApi
from scan2hive.hive.result import HiveResult
from scan2hive.log import LoggerManager
from scan2hive.parsers.enums import ToolType

logger = LoggerManager.get_logger()


def chunked(iterable: Iterable, chunk_size: int):
    iterator = iter(iterable)
    while True:
        chunk = list(itertools.islice(iterator, chunk_size))
        if not chunk:
            break
        yield chunk


class Uploader():
    def __init__(self, output: HiveResult, tool: ToolType, server: str, project: str, chunk_size: int, *args, **kwargs):
        self._server = server
        self._project = project
        self._username: str = input("Enter username for Hive: ")
        self._password: str = getpass(f"Enter password for Hive user '{self._username}': ")
        self._chunk_size = chunk_size
        self._hosts = output.hosts
        self.tool = tool

        try:
            self._hive_api = HiveRestApi(username=self._username, password=self._password,
                                         server=self._server, debug=True)
        except Exception as e:
            logger.error(e)
            exit(1)

    def _make_snapshot(self):
        logger.info("Trying to create snapshot")
        snapshot: HiveLibrary.Snapshot = self._hive_api.make_snapshot(project_id=self._project,
                                                                      name=f"before {self.tool.as_str} result importing",
                                                                      description=f"before {self.tool.as_str} result importing with script")
        if snapshot:
            logger.info(f"Snapshot '{snapshot.name}' was created at {snapshot.timestamp}")
        else:
            logger.warning("Cannot create snapshot")

    def _upload_hosts(self):
        self._make_snapshot()

        logger.debug(f"Uploading {len(self._hosts)} hosts. Chunk size is {self._chunk_size}.")
        chunk_number = 1
        for chunk in chunked(self._hosts, self._chunk_size):
            logger.debug(f"Chunk {chunk_number}")
            self._hive_api.create_hosts(project_id=self._project, hosts=chunk)
            chunk_number += 1
        logger.info("Hosts were uploaded")

    def upload(self):
        self._upload_hosts()


class UploaderFactory:
    _items: ClassVar[Dict[ToolType, Type[Uploader]]] = {}

    @classmethod
    def register(cls, typ: ToolType, klass: Type[Uploader]):
        if typ not in cls._items:
            cls._items[typ] = klass
            logger.debug(f"Registered '{klass.__name__}' for type '{typ.name}'")
        else:
            msg = f"Uploader class '{klass.__name__}' with type '{typ.name}' is already registered"
            logger.error(msg)
            raise KeyError(msg)

    @classmethod
    def get(cls, typ: ToolType) -> Type[Uploader]:
        if typ not in cls._items:
            return Uploader
        else:
            return cls._items[typ]


def register_uploader(cls=None, /, *, typ: ToolType = ToolType.Unknown):
    def wrap(cls):
        if typ != ToolType.Unknown:
            UploaderFactory.register(typ, cls)
            return cls

    if cls is None:
        return wrap

    return wrap(cls)
