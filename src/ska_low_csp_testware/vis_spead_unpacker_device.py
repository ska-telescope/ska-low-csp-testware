"""
TANGO device to unpack visibility SPEAD data from a PCAP file.
"""

import hashlib
import logging
import os
from functools import partial

import asyncio
import concurrent.futures
import pandas
import spead2
import spead2.recv
from tango import GreenMode, DevState
from tango.server import Device, device_property, command, attribute, run

from ska_low_csp_testware.spead import process_pcap_file, SpeadHeapVisitor

__all__ = ["VisSpeadUnpacker", "main"]

logger = logging.getLogger(__name__)


class ExtractVisibilityMetadata(SpeadHeapVisitor):
    """
    Extract visibility metadata from the SPEAD headers.
    """

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


class VisSpeadUnpacker(Device):
    """
    TANGO device to unpack visibility SPEAD data from a PCAP file.
    """

    green_mode = GreenMode.Asyncio

    pcap_dir = device_property(dtype="DevString")

    _metadata: dict[str, pandas.DataFrame] = {}

    async def init_device(self):
        await super().init_device()
        self._metadata = {}
        self.set_state(DevState.ON)

    def metadata_read(self, attr):
        attr_name = attr.get_name().removesuffix("_metadata")
        value = self._metadata[attr_name]
        attr.set_value(value.to_json())

    @command
    async def Unpack(self, file_name: str) -> str:
        """Unpack a PCAP file."""
        file_hash = hashlib.sha1(file_name.encode()).hexdigest()
        if file_hash in self._metadata:
            return file_hash

        loop = asyncio.get_event_loop()
        loop.create_task(self._unpack(file_name, file_hash))
        return file_hash

    async def _unpack(self, file_name: str, file_hash: str) -> None:
        file_path = os.path.join(self.pcap_dir, file_name)
        self.info_stream(f"Unpacking PCAP file {file_path}")
        loop = asyncio.get_event_loop()
        with concurrent.futures.ThreadPoolExecutor() as pool:
            visitor = ExtractVisibilityMetadata()
            await loop.run_in_executor(pool, partial(process_pcap_file, file_path, visitor))
            self._metadata[file_hash] = visitor.metadata

            attr = attribute(
                name=f"{file_hash}_metadata",
                label=f"Metadata unpacked from {file_name}",
                dtype=str,
                fget=self.metadata_read,
            )
            self.add_attribute(attr)


def main(args=None, **kwargs):
    """Main entrypoint."""
    return run((VisSpeadUnpacker,), args=args, **kwargs)


if __name__ == "__main__":
    main()
