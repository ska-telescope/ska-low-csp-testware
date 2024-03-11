# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,broad-exception-caught

import pandas
import spead2
import spead2.recv
from ska_tango_base.base import SKABaseDevice
from tango.server import attribute, command, device_property

from ska_low_csp_testware.pcap_file_component_manager import PcapFileComponentManager
from ska_low_csp_testware.spead import SpeadHeapVisitor, process_pcap_file

__all__ = ["PcapFileDevice"]


class ExtractVisibilityMetadata(SpeadHeapVisitor):
    def __init__(self) -> None:
        self._metadata = []

    def visit_start_of_stream_heap(self, heap: spead2.recv.Heap, items: dict[str, spead2.Item]) -> None:
        row = {}
        for key, item in items.items():
            row[key] = item.value
        self._metadata.append(row)

    @property
    def metadata(self) -> pandas.DataFrame:
        return pandas.DataFrame(self._metadata)


class PcapFileDevice(SKABaseDevice):
    pcap_file_path: str = device_property()  # type: ignore

    _metadata: pandas.DataFrame | None = None

    def create_component_manager(self) -> PcapFileComponentManager:
        return PcapFileComponentManager(
            pcap_file_path=self.pcap_file_path,
            logger=self.logger,
            communication_state_callback=self._communication_state_changed,
            component_state_callback=self._component_state_changed,
        )

    @attribute
    def metadata(self) -> str:
        if self._metadata is None:
            return "{}"

        return self._metadata.to_json()

    @command
    def load(self) -> None:
        self.logger.debug("Start unpacking file")
        visitor = ExtractVisibilityMetadata()
        process_pcap_file(self.pcap_file_path, visitor)
        self._metadata = visitor.metadata
        self.logger.debug("Finished unpacking file")
