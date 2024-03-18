"""
Utilities to work with the ``spead2`` library.
"""

import logging
from pathlib import Path
from typing import Generator

import spead2
import spead2.recv

module_logger = logging.getLogger(__name__)


def read_pcap_file(
    pcap_file_path: Path,
    logger: logging.Logger | None = None,
) -> Generator[tuple[spead2.recv.Heap, dict[str, spead2.Item]], None, None]:
    """
    Read a PCAP file at the given path.

    :param pcap_file_path: Path to the PCAP file to read.
    :param logger: Python logger.
    :returns: A generator that yields each SPEAD heap contained in the PCAP file,
              along with the SPEAD items contained in that heap.
    """
    logger = logger or module_logger
    stream = spead2.recv.Stream(spead2.ThreadPool())
    stream.add_udp_pcap_file_reader(str(pcap_file_path), filter="")
    item_group = spead2.ItemGroup()
    heap_number = 0

    try:
        logger.info("Start reading SPEAD data from file: %s", pcap_file_path)
        for heap_number, heap in enumerate(stream):
            if heap_number == 0:
                logger.info(
                    "SPEAD flavour: SPEAD-%d-%d v%s",
                    heap.flavour.item_pointer_bits,
                    heap.flavour.heap_address_bits,
                    heap.flavour.version,
                )

            yield heap, item_group.update(heap)
        logger.info("Finished reading %d SPEAD heaps from file: %s", heap_number + 1, pcap_file_path)
    finally:
        stream.stop()
