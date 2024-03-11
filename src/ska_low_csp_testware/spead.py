"""
Module to read SPEAD data using the ``spead2`` library.
"""

import abc
import logging
import threading

import spead2
import spead2.recv

__all__ = ["read_pcap_file", "SpeadHeapVisitor"]


class SpeadHeapVisitor(abc.ABC):
    """Abstract base class to process individual SPEAD heaps."""

    def visit_start_of_stream_heap(self, heap: spead2.recv.Heap, items: dict[str, spead2.Item]) -> None:
        """
        Visit a start-of-stream heap.

        :param heap: The start-of-stream heap to visit
        :param items: The items in the heap
        """

    def visit_data_heap(self, heap: spead2.recv.Heap, items: dict[str, spead2.Item]) -> None:
        """
        Visit a data heap.

        :param heap: The data heap to visit
        :param items: The items in the heap
        """

    def visit_end_of_stream_heap(self, heap: spead2.recv.Heap, items: dict[str, spead2.Item]) -> None:
        """
        Visit an end-of-stream heap.

        :param heap: The end-of-stream heap to visit
        :param items: The items in the heap
        """


def read_pcap_file(
    pcap_file_path: str,
    visitors: list[SpeadHeapVisitor],
    logger: logging.Logger,
    task_abort_event: threading.Event | None = None,
) -> None:
    """Read a PCAP file containing SPEAD data."""
    logger.info("Start reading SPEAD data from file: %s", pcap_file_path)
    stream = spead2.recv.Stream(spead2.ThreadPool())
    stream.add_udp_pcap_file_reader(pcap_file_path, filter="")
    item_group = spead2.ItemGroup()
    heap_number = 0

    for heap_number, heap in enumerate(stream):
        if task_abort_event is not None and task_abort_event.is_set():
            logger.info("Abort reading SPEAD data from file: %s", pcap_file_path)
            stream.stop()
            return

        items = item_group.update(heap)

        if heap_number == 0:
            logger.info(
                "SPEAD flavour: SPEAD-%d-%d v%s",
                heap.flavour.item_pointer_bits,
                heap.flavour.heap_address_bits,
                heap.flavour.version,
            )

        if heap.is_start_of_stream():
            for visitor in visitors:
                visitor.visit_start_of_stream_heap(heap, items)
            continue

        if heap.is_end_of_stream():
            for visitor in visitors:
                visitor.visit_end_of_stream_heap(heap, items)
            continue

        for visitor in visitors:
            visitor.visit_data_heap(heap, items)

    stream.stop()
    logger.info("Finished reading %d SPEAD heaps from file: %s", heap_number + 1, pcap_file_path)
