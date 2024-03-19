"""
Unit tests for the :py:class:`ska_low_csp_testware.pcap_file_device.PcapFile` TANGO device.
"""

import io
import time
from pathlib import Path

import numpy as np
import numpy.typing as npt
import pandas as pd
import pytest
from ska_control_model import TestMode
from ska_tango_testing.mock.tango import MockTangoEventCallbackGroup
from tango import DevFailed, DeviceProxy, DevState, EventType
from tango.test_context import DeviceTestContext

from ska_low_csp_testware.common_types import DataType
from ska_low_csp_testware.pcap_file_device import PcapFile


@pytest.fixture(name="pcap_file")
def fxt_pcap_file(tmp_path: Path):
    """
    Fixture that creates a sample PCAP file to pass to the TANGO device.
    """
    pcap_file = tmp_path / "sample_file.pcap"
    pcap_file.touch()
    return pcap_file


@pytest.fixture(name="change_event_callbacks")
def fxt_change_event_callbacks():
    """
    Fixture that returns a :py:class:`MockTangoEventCallbackGroup` used to capture change event callbacks.
    """
    return MockTangoEventCallbackGroup(
        "file_size",
        "file_time_modified",
        "state",
    )


@pytest.fixture(name="device")
def fxt_device(pcap_file: Path):
    """
    Fixture that sets up a new test context in which the TANGO device is started.
    """
    with DeviceTestContext(
        PcapFile,
        properties={
            "pcap_file_path": str(pcap_file),
            "test_mode": TestMode.TEST.value,
        },
        process=True,
    ) as device:
        yield device


@pytest.mark.debug
@pytest.mark.forked
def test_file_attributes_react_to_changes(
    pcap_file: Path,
    device: DeviceProxy,
    change_event_callbacks: MockTangoEventCallbackGroup,
):
    """
    Test that verifies that the ``file_*`` TANGO attributes are automatically updated and change events are pushed
    whenever the underlying file is updated.
    """
    assert device.state() == DevState.ON

    original_size = device.file_size
    original_time_modified = device.file_time_modified

    for attr_name in ["file_size", "file_time_modified"]:
        device.subscribe_event(
            attr_name,
            EventType.CHANGE_EVENT,
            change_event_callbacks[attr_name],
        )

    time.sleep(0.5)

    change_event_callbacks["file_size"].assert_change_event(original_size)
    change_event_callbacks["file_time_modified"].assert_change_event(original_time_modified)

    with pcap_file.open("w", encoding="utf8") as writer:
        writer.write("Hello, world!")

    time.sleep(1)

    assert device.file_size == 13
    assert device.file_time_modified > original_time_modified
    change_event_callbacks["file_size"].assert_change_event(device.file_size)
    change_event_callbacks["file_time_modified"].assert_change_event(device.file_time_modified)


@pytest.mark.forked
def test_delete_file_command(
    pcap_file: Path,
    device: DeviceProxy,
):
    """
    Test case for the ``DeleteFile`` command.

    When invoked, the TANGO device should remove the underlying PCAP file from disk,
    and then switch itself off.

    Note: in isolation this behavior might not make much sense, but in a real system the
    :py:class:`ska_low_csp_testware.pcap_file_monitor_device.PcapFileMonitor` will notice that the file is removed
    and remove this TANGO device as a result.
    """
    device.DeleteFile()
    assert not pcap_file.exists()
    time.sleep(1)
    assert device.state() == DevState.OFF


@pytest.mark.forked
def test_read_file_command_vis(
    device: DeviceProxy,
):
    """
    Test case for the ``ReadFile`` command using the ``DataType.VIS`` data type.
    """
    headers_json, data_bytes = device.ReadFile(DataType.VIS)

    headers: pd.DataFrame = pd.read_json(io.StringIO(headers_json))
    assert headers.size > 0  # pylint: disable=no-member

    data_buf = io.BytesIO()
    data_buf.write(data_bytes)
    data_buf.seek(0)
    data: npt.NDArray = np.load(data_buf)
    assert data.dtype == np.complex64


@pytest.mark.forked
def test_read_file_command_unknown_data_type(device: DeviceProxy):
    """
    Test case for the ``ReadFile`` command using an unknown data type.
    """
    with pytest.raises(DevFailed):
        device.ReadFile(42)
