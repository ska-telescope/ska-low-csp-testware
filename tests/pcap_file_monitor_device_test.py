"""
Unit tests for the :py:class:`ska_low_csp_testware.pcap_file_monitor_device.PcapFileMonitor` TANGO device.
"""

import time
from pathlib import Path

import pytest
from ska_control_model import TestMode
from ska_tango_testing.mock.tango import MockTangoEventCallbackGroup
from tango import DeviceProxy, EventType
from tango.test_context import DeviceTestContext

from ska_low_csp_testware.pcap_file_monitor_device import PcapFileMonitor


@pytest.fixture(name="pcap_dir")
def fxt_pcap_dir(tmp_path: Path):
    """
    Fixture that sets up a PCAP directory being monitored.
    """
    tmp_path.joinpath("existing_pcap_file.pcap").touch()
    tmp_path.joinpath("existing_txt_file.txt").touch()
    return tmp_path


@pytest.fixture(name="change_event_callbacks")
def fxt_change_event_callbacks():
    """
    Fixture that returns a :py:class:`MockTangoEventCallbackGroup` used to capture change event callbacks.
    """
    return MockTangoEventCallbackGroup(
        "files",
    )


@pytest.fixture(name="device")
def fxt_device(pcap_dir: Path):
    """
    Fixture that sets up a new test context in which the TANGO device is started.
    """
    with DeviceTestContext(
        PcapFileMonitor,
        properties={"pcap_dir": str(pcap_dir), "test_mode": TestMode.TEST.value},
        process=True,
    ) as device:
        yield device


@pytest.mark.debug
@pytest.mark.forked
def test_files_attribute_reacts_to_created_pcap_file(
    pcap_dir: Path,
    device: DeviceProxy,
    change_event_callbacks: MockTangoEventCallbackGroup,
):
    """
    Test that verifies that the ``files`` TANGO attribute is automatically updated and change events are pushed
    whenever a PCAP file is created.
    """
    device.subscribe_event(
        "files",
        EventType.CHANGE_EVENT,
        change_event_callbacks["files"],
    )

    time.sleep(0.5)
    assert "existing_pcap_file.pcap" in device.files
    change_event_callbacks["files"].assert_change_event(device.files)

    pcap_file = pcap_dir / "new_pcap_file.pcap"
    pcap_file.touch()
    time.sleep(2)

    assert pcap_file.name in device.files
    change_event_callbacks["files"].assert_change_event(device.files)


@pytest.mark.debug
@pytest.mark.forked
def test_files_attribute_reacts_to_removed_pcap_file(
    pcap_dir: Path,
    device: DeviceProxy,
    change_event_callbacks: MockTangoEventCallbackGroup,
):
    """
    Test that verifies that the ``files`` TANGO attribute is automatically updated and change events are pushed
    whenever a PCAP file is removed.
    """
    device.subscribe_event(
        "files",
        EventType.CHANGE_EVENT,
        change_event_callbacks["files"],
    )

    time.sleep(0.5)
    assert "existing_pcap_file.pcap" in device.files
    change_event_callbacks["files"].assert_change_event(device.files)

    pcap_dir.joinpath("existing_pcap_file.pcap").unlink()
    time.sleep(2)

    assert "existing_pcap_file.pcap" not in device.files
    change_event_callbacks["files"].assert_change_event(device.files)
