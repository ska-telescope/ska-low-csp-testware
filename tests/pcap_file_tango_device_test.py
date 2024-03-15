"""
Unit tests for the :py:class:`ska_low_csp_testware.pcap_file_device.PcapFile` TANGO device.
"""

from pathlib import Path

import pytest
import tango
from ska_control_model import AdminMode
from ska_tango_testing.mock import placeholders
from ska_tango_testing.mock.tango import MockTangoEventCallbackGroup
from tango.test_context import DeviceTestContext

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
        "heap_count",
        "spead_headers",
        "state",
    )


@pytest.fixture(name="device")
def fxt_device(pcap_file: Path):
    """
    Fixture that sets up a new test context in which the TANGO device is started.
    """
    with DeviceTestContext(PcapFile, properties={"pcap_file_path": [str(pcap_file)]}) as proxy:
        yield proxy


@pytest.mark.forked
def test_file_attributes_react_to_changes(
    pcap_file: Path,
    device: tango.DeviceProxy,
    change_event_callbacks: MockTangoEventCallbackGroup,
):
    """
    Test that verifies that the ``file_*`` TANGO attributes are automatically updated and change events are pushed
    whenever the underlying file is updated.
    """
    device.adminmode = AdminMode.ONLINE
    for attr_name in ["file_size", "file_time_modified"]:
        device.subscribe_event(
            attr_name,
            tango.EventType.CHANGE_EVENT,
            change_event_callbacks[attr_name],
        )

    change_event_callbacks["file_size"].assert_change_event(0)
    change_event_callbacks["file_time_modified"].assert_change_event(placeholders.Anything)

    with pcap_file.open("w", encoding="utf8") as writer:
        writer.write("Hello, world!")

    change_event_callbacks["file_size"].assert_change_event(13)
    change_event_callbacks["file_time_modified"].assert_change_event(placeholders.Anything)


@pytest.mark.forked
def test_delete_command(
    pcap_file: Path,
    device: tango.DeviceProxy,
    change_event_callbacks: MockTangoEventCallbackGroup,
):
    """
    Test case for the ``Delete`` command.

    When invoked, the TANGO device should remove the underlying PCAP file from disk,
    and then switch itself off.

    Note: in isolation this behavior might not make much sense, but in a real system the
    :py:class:`ska_low_csp_testware.pcap_file_monitor_device.PcapFileMonitor` will notice that the file is removed
    and shut down this TANGO device as a result.
    """
    device.adminmode = AdminMode.ONLINE
    device.subscribe_event(
        "state",
        tango.EventType.CHANGE_EVENT,
        change_event_callbacks["state"],
    )

    change_event_callbacks["state"].assert_change_event(
        tango.DevState.ON,
        lookahead=2,
        consume_nonmatches=True,
    )

    device.Delete()

    change_event_callbacks["state"].assert_change_event(tango.DevState.DISABLE)

    assert not pcap_file.exists()
