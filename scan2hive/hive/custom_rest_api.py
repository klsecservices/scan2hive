from json.decoder import JSONDecodeError
from typing import List, Optional, Dict
from uuid import UUID
from ipaddress import IPv6Address

from hive_library import HiveLibrary
from hive_library.rest import HiveRestApi
from marshmallow import (
    fields
)

class CustomHost(HiveLibrary.Host):
    ipv6: Optional[IPv6Address] = None

# serialize "extra" field
class CustomRecordSchema(HiveLibrary.Record.Schema):
    extra = fields.String(load_only=False)


# server does not know what "text" is, but it wants "note"
class NoteSchema(HiveLibrary.Note.Schema):
    text = fields.String(load_default=None, data_key="note")


# serialize records with "extra" field and notes with "note" (notes were not serialized by default)
class CustomPortSchema(HiveLibrary.Host.Port.Schema):
    notes = fields.Nested(
        lambda: NoteSchema,
        load_only=False,
        many=True,
        load_default=[],
        allow_none=True,
    )
    records = fields.Nested(
        lambda: CustomRecordSchema,
        many=True,
        load_default=[],
    )

# use custom schemas and serialize notes
class CustomHostSchema(HiveLibrary.Host.Schema):
    ipv6 = fields.IPv6(missing=None, default=None, allow_none=True)
    notes = fields.Nested(
        lambda: NoteSchema,
        load_only=False,
        many=True,
        data_key="notes",
        load_default=[],
        allow_none=True,
    )

    records = fields.Nested(
        lambda: CustomRecordSchema,
        many=True,
        load_default=[],
    )

    ports = fields.Nested(
        lambda: CustomPortSchema,
        many=True,
        load_default=[],
    )


# use custom host serialization schema
class CustomHiveRestApi(HiveRestApi):

    def create_hosts(self, project_id: UUID, hosts: List[HiveLibrary.Host]) -> Optional[UUID]:
        try:
            hosts_schema: CustomHostSchema = CustomHostSchema(many=True)
            response = self._session.post(
                self._server + self._endpoints.project + f"/{project_id}/graph/api",
                json=hosts_schema.dump(hosts),
            )
            error_string: str = ""
            if self._debug:
                error_string = self._make_error_string(response)
            assert (
                    response.status_code == 200
            ), f"Bad status code in create hosts {error_string}"
            assert isinstance(
                response.json(), Dict
            ), f"Bad response in create hosts {error_string}"
            assert (
                    "taskId" in response.json()
            ), f"Not found key taskId in create hosts response {error_string}"
            assert isinstance(
                response.json()["taskId"], str
            ), f"Bad value for key taskId in create hosts response {error_string}"
            return UUID(response.json()["taskId"])
        except AssertionError as error:
            print(f"Assertion error: {error.args[0]}")
            return None
        except JSONDecodeError as error:
            print(f"JSON Decode error: {error.args[0]}")
            return None
