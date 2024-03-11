# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring

from dataclasses import dataclass

import pandas

__all__ = ["PcapFileMetadata"]


@dataclass
class PcapFileMetadata:
    heap_count: int
    spead_headers: pandas.DataFrame
