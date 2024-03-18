"""
Common types shared between modules.
"""

from dataclasses import dataclass
from enum import IntEnum

import numpy.typing as npt
import pandas as pd

__all__ = [
    "DataType",
    "PcapFileContents",
]


class DataType(IntEnum):
    """
    The type of data contained in the PCAP file.
    """

    VIS = 0
    """
    Visibility data received from LOW-CBF.
    """


@dataclass
class PcapFileContents:
    """
    The contents of the PCAP file.
    """

    spead_heap_count: int
    spead_headers: pd.DataFrame
    spead_data: npt.NDArray
