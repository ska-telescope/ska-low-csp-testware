"""
Module containing helpers to read LOW CBF visibility data.
"""

import base64
import io
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
import numpy.typing as npt
import pandas as pd
from ska_control_model import TestMode

from ska_low_csp_testware import spead2_util

__all__ = ["read_visibilities"]


def _encode_dataframe(df: pd.DataFrame) -> bytes:
    buffer = io.BytesIO()
    df.to_pickle(buffer)
    return buffer.getvalue()


def _encode_ndarray(array: npt.NDArray) -> bytes:
    buffer = io.BytesIO()
    np.save(buffer, array)
    return buffer.getvalue()


class BytesEncoder(json.JSONEncoder):
    """
    Custom JSON encoder that allows encoding of ``bytes``.
    """

    def default(self, o: Any) -> Any:
        if isinstance(o, bytes):
            return base64.b64encode(o).decode("ascii")
        return super().encode(o)


@dataclass
class VisibilityData:
    """
    The contents of the PCAP file.
    """

    spead_headers: pd.DataFrame
    spead_data: npt.NDArray

    def to_json(self) -> str:
        """
        Encode the PCAP file contents to JSON.
        """
        return json.dumps(
            {
                "headers": _encode_dataframe(self.spead_headers),
                "averaged_data": _encode_ndarray(self.spead_data),
            },
            cls=BytesEncoder,
        )


FAKE_VISIBILITIES = VisibilityData(
    spead_headers=pd.DataFrame({"col1": [1, 2], "col2": [3, 4]}),
    spead_data=np.zeros((2, 2), dtype=np.complex64),
)


def read_visibilities(
    pcap_file_path: Path,
    test_mode: TestMode = TestMode.NONE,
    logger: logging.Logger | None = None,
) -> VisibilityData:
    """
    Read LOW-CBF visibility data from a PCAP file.
    """

    match test_mode:
        case TestMode.NONE:
            return _read_visibilities(pcap_file_path, logger=logger)
        case TestMode.TEST:
            return FAKE_VISIBILITIES


def _read_visibilities(
    pcap_file_path: Path,
    logger: logging.Logger | None = None,
) -> VisibilityData:
    headers = []
    averaged_data: dict[int, npt.NDArray[np.complex64]] = {}

    for heap, items in spead2_util.read_pcap_file(pcap_file_path, logger=logger):
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

    return VisibilityData(
        spead_headers=pd.DataFrame(headers),
        spead_data=np.stack(list(averaged_data.values())),
    )
