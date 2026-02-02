from bs4 import BeautifulSoup, element
from pathlib import Path

from scan2hive.log import LoggerManager

logger = LoggerManager.get_logger()


class XMLLoadingMixin:
    @staticmethod
    def _load_xml(path: Path, root_tag: str) -> element.Tag:
        try:
            xml_text = path.read_text(encoding="utf-8", errors="ignore")
            soup = BeautifulSoup(xml_text, "xml")
            root = soup.find(root_tag)
            return root
        except:
            logger.error(f"cannot load data from xml file '{path.as_posix()}'.")
            exit(1)

    @staticmethod
    def _validate_xml_data(root: BeautifulSoup) -> bool:
        raise NotImplementedError
