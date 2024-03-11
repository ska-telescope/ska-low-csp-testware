# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring

import logging

import pytest
from spead2 import Item
from spead2.recv import Heap

from ska_low_csp_testware.spead import SpeadHeapVisitor, read_pcap_file


class _HeapCounter(SpeadHeapVisitor):
    def __init__(self) -> None:
        self.start_of_stream_heap_count = 0
        self.data_heap_count = 0
        self.end_of_stream_heap_count = 0

    def visit_start_of_stream_heap(self, heap: Heap, items: dict[str, Item]) -> None:
        self.start_of_stream_heap_count += 1

    def visit_data_heap(self, heap: Heap, items: dict[str, Item]) -> None:
        self.data_heap_count += 1

    def visit_end_of_stream_heap(self, heap: Heap, items: dict[str, Item]) -> None:
        self.end_of_stream_heap_count += 1


@pytest.fixture(name="logger")
def fxt_logger():
    return logging.getLogger(__name__)


def test_read_pcap_file(logger):
    heap_counter = _HeapCounter()
    read_pcap_file("tests/vis.pcap", [heap_counter], logger)
    assert heap_counter.start_of_stream_heap_count == 1152
    assert heap_counter.data_heap_count == 10368
    assert heap_counter.end_of_stream_heap_count == 0
