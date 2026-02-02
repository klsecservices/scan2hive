from hive_library import HiveLibrary
from pathlib import Path
from typing import List, Optional

from scan2hive.hive.custom_rest_api import HiveRestApi
from scan2hive.hive.result import ScreenshotDescriptor
from scan2hive.log import LoggerManager

logger = LoggerManager.get_logger()


class ScreenshotsUploadingMixin:
    # можно ли сюда Self и брать параметры от него. 
    @staticmethod
    def _upload_screenshots(screendhot_descriptors: List[ScreenshotDescriptor], hive_api: HiveRestApi, project: str):
        logger.debug("Uploading screenshots")
        if screendhot_descriptors is not None:
            for it in screendhot_descriptors:
                port_id = hive_api.get_port_id(project_id=project, port=it.port, ip=it.ip)
                new_file: Optional[HiveLibrary.Tag] = hive_api.upload_file(file_name="screenshot.jpeg",
                                                                           file_content=it.screenshot_data,
                                                                           node_id=port_id, project_id=project)
                if new_file is None:
                    logger.warning(f"Error uploading file for port_id {port_id}")
            logger.info("Screenshots were uploaded")
        else:
            logger.info(f"Screenshots were not be uploaded")
