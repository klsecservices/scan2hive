from typing import List

from scan2hive.hive.result import GowitnessHiveResult, ScreenshotDescriptor
from scan2hive.log import LoggerManager
from scan2hive.parsers.enums import ToolType
from scan2hive.uploaders.base import Uploader, register_uploader
from scan2hive.uploaders.mixins.screenshots_uploading_mixin import ScreenshotsUploadingMixin

logger = LoggerManager.get_logger()


@register_uploader(typ=ToolType.Gowitness)
class GowitnessUploader(Uploader, ScreenshotsUploadingMixin):
    def __init__(self, output: GowitnessHiveResult, tool: ToolType, server: str, project: str, chunk_size: int, *args,
                 **kwargs):
        super().__init__(output, tool, server, project, chunk_size, *args, **kwargs)
        self._screendhot_descriptors: List[ScreenshotDescriptor] = output.screendhot_descriptors

    def upload(self):
        super().upload()
        self._upload_screenshots(screendhot_descriptors=self._screendhot_descriptors,
                                 hive_api=self._hive_api, project=self._project)
