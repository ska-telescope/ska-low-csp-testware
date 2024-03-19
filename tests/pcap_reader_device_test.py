"""
Unit tests for the :py:class:`ska_low_csp_testware.pcap_reader_device.PcapReader` TANGO device.
"""

import json
import time
from pathlib import Path

import pytest
from ska_control_model import TestMode
from ska_tango_testing.mock.tango import MockTangoEventCallbackGroup
from tango import DeviceProxy, EventType
from tango.test_context import DeviceTestContext

from ska_low_csp_testware.pcap_reader_device import PcapReader

pytestmark = pytest.mark.forked


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
        PcapReader,
        properties={
            "pcap_dir": str(pcap_dir),
            "test_mode": TestMode.TEST.value,
        },
        process=True,
        debug=4,
    ) as device:
        yield device


def test_files_attribute_reacts_to_created_pcap_file(
    pcap_dir: Path,
    device: DeviceProxy,
    change_event_callbacks: MockTangoEventCallbackGroup,
):
    """
    Test that verifies that the ``files`` TANGO attribute is automatically updated and change events are pushed
    whenever a PCAP file is created.
    """
    existing_files = device.files

    device.subscribe_event(
        "files",
        EventType.CHANGE_EVENT,
        change_event_callbacks["files"],
    )

    time.sleep(0.5)
    change_event_callbacks["files"].assert_change_event(existing_files)

    pcap_file = pcap_dir / "new_pcap_file.pcap"
    pcap_file.touch()
    time.sleep(0.5)

    assert pcap_file.name in json.loads(device.files)
    change_event_callbacks["files"].assert_change_event(device.files)
