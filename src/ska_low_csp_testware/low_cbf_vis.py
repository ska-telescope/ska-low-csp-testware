"""
Module containing helpers to read LOW CBF visibility data.
"""

import logging
import threading
from pathlib import Path
from typing import Callable

import numpy as np
import numpy.typing as npt
import pandas as pd
from ska_control_model import TaskStatus
from ska_tango_base.base import TaskCallbackType

from ska_low_csp_testware import spead2_util
from ska_low_csp_testware.common_types import PcapFileContents

__all__ = ["ReadLowCbfVisibilitiesTask"]

module_logger = logging.getLogger(__name__)


class ReadLowCbfVisibilitiesTask:  # pylint: disable=too-few-public-methods
    """
    Long-running task that reads LOW-CBF visibility data from a PCAP file.
    """

    def __init__(
        self,
        pcap_file_path: Path,
        result_callback: Callable[[PcapFileContents], None],
        logger: logging.Logger | None = None,
    ) -> None:
        self._pcap_file_path = pcap_file_path
        self._result_callback = result_callback
        self._logger = logger or module_logger

        self._heap_count = 0
        self._metadata = []
        self._averaged_data: dict[int, npt.NDArray[np.complex64]] = {}

    def __call__(
        self,
        task_callback: TaskCallbackType,
        task_abort_event: threading.Event,
    ) -> None:
        for heap, items in spead2_util.read_pcap_file(self._pcap_file_path, self._logger):
            if task_abort_event.is_set():
                task_callback(status=TaskStatus.ABORTED)
                return

            task_callback(status=TaskStatus.IN_PROGRESS)
            self._heap_count += 1

            if heap.is_start_of_stream():
                row = {}
                for key, item in items.items():
                    row[key] = item.value
                self._metadata.append(row)
                continue

            if heap.is_end_of_stream():
                continue

            channel_id = int.from_bytes(bytearray(heap.cnt.to_bytes(6, byteorder="big"))[2:4], "big")
            if item := items.get("Corre", None):
                data = item.value["VIS"]
                if channel_id in self._averaged_data:
                    self._averaged_data[channel_id] = np.average(
                        np.array([self._averaged_data[channel_id], data]),
                        axis=0,
                    )
                else:
                    self._averaged_data[channel_id] = data

        result = PcapFileContents(
            spead_heap_count=self._heap_count,
            spead_headers=pd.DataFrame(self._metadata),
            spead_data=np.stack(list(self._averaged_data.values())),
        )
        self._result_callback(result)
        task_callback(TaskStatus.COMPLETED)
