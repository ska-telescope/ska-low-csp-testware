"""
Module containing helpers to read LOW CBF visibility data.
"""

import logging
from pathlib import Path

import numpy as np
import numpy.typing as npt
import pandas as pd
from ska_control_model import TestMode

from ska_low_csp_testware import spead2_util
from ska_low_csp_testware.common_types import PcapFileContents

__all__ = ["read_visibilities"]

module_logger = logging.getLogger(__name__)

FAKE_VISIBILITIES = PcapFileContents(
    spead_headers=pd.DataFrame({"col1": [1, 2], "col2": [3, 4]}),
    spead_data=np.zeros((2, 2), dtype=np.complex64),
)


async def read_visibilities(pcap_file_path: Path, test_mode: TestMode = TestMode.NONE) -> PcapFileContents:
    """
    Read LOW-CBF visibility data from a PCAP file.
    """

    match test_mode:
        case TestMode.NONE:
            return await _read_visibilities(pcap_file_path)
        case TestMode.TEST:
            return FAKE_VISIBILITIES


async def _read_visibilities(pcap_file_path: Path) -> PcapFileContents:
    headers = []
    averaged_data: dict[int, npt.NDArray[np.complex64]] = {}

    async for heap, items in spead2_util.read_pcap_file(pcap_file_path, logger=module_logger):
        if heap.is_start_of_stream():
            row = {}
            for key, item in items.items():
                row[key] = item.value
            headers.append(row)
            continue

        if heap.is_end_of_stream():
            continue

        channel_id = int.from_bytes(bytearray(heap.cnt.to_bytes(6, byteorder="big"))[2:4], "big")
        if item := items.get("Corre", None):
            data = item.value["VIS"]
            if channel_id in averaged_data:
                averaged_data[channel_id] = np.average(
                    np.array([averaged_data[channel_id], data]),
                    axis=0,
                )
            else:
                averaged_data[channel_id] = data

    return PcapFileContents(
        spead_headers=pd.DataFrame(headers),
        spead_data=np.stack(list(averaged_data.values())),
    )
