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

pytestmark = pytest.mark.forked


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
        "file_modification_datetime",
        "file_modification_timestamp",
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
    original_modification_datetime = device.file_modification_datetime
    original_modification_timestamp = device.file_modification_timestamp

    for attr_name in [
        "file_size",
        "file_modification_datetime",
        "file_modification_timestamp",
    ]:
        device.subscribe_event(
            attr_name,
            EventType.CHANGE_EVENT,
            change_event_callbacks[attr_name],
        )

    time.sleep(0.5)

    change_event_callbacks["file_size"].assert_change_event(original_size)
    change_event_callbacks["file_modification_datetime"].assert_change_event(original_modification_datetime)
    change_event_callbacks["file_modification_timestamp"].assert_change_event(original_modification_timestamp)

    with pcap_file.open("w", encoding="utf8") as writer:
        writer.write("Hello, world!")

    time.sleep(0.5)

    assert device.file_size == 13
    assert device.file_modification_datetime > original_modification_datetime
    assert device.file_modification_timestamp > original_modification_timestamp
    change_event_callbacks["file_size"].assert_change_event(device.file_size)
    change_event_callbacks["file_modification_datetime"].assert_change_event(device.file_modification_datetime)
    change_event_callbacks["file_modification_timestamp"].assert_change_event(device.file_modification_timestamp)


def test_delete_file_command(pcap_file: Path, device: DeviceProxy):
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


def test_read_file_command_vis(device: DeviceProxy):
    """
    Test case for the ``ReadFile`` command using the ``DataType.VIS`` data type.
    """
    device.data_type = DataType.VIS
    headers_json, data_bytes = device.ReadFile()

    headers: pd.DataFrame = pd.read_json(io.StringIO(headers_json))
    assert headers.size > 0  # pylint: disable=no-member

    data_buf = io.BytesIO()
    data_buf.write(data_bytes)
    data_buf.seek(0)
    data: npt.NDArray = np.load(data_buf)
    assert data.dtype == np.complex64


def test_read_file_command_no_data_type(device: DeviceProxy):
    """
    Test case for the ``ReadFile`` command when no data type is configured.
    """
    device.data_type = DataType.NOT_CONFIGURED
    with pytest.raises(DevFailed):
        device.ReadFile()
