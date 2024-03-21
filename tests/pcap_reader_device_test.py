# pylint: disable=missing-module-docstring,missing-function-docstring,missing-class-docstring

import json
import time
from pathlib import Path

import pytest
from ska_control_model import TestMode
from ska_tango_testing.mock import placeholders
from ska_tango_testing.mock.tango import MockTangoEventCallbackGroup
from tango import DeviceProxy, EventType
from tango.test_context import DeviceTestContext

from ska_low_csp_testware.pcap_reader_device import PcapReader

pytestmark = pytest.mark.forked


@pytest.fixture(name="pcap_dir")
def fxt_pcap_dir(tmp_path: Path):
    tmp_path.joinpath("existing_pcap_file.pcap").touch()
    tmp_path.joinpath("existing_txt_file.txt").touch()
    return tmp_path


@pytest.fixture(name="event_callbacks")
def fxt_event_callbacks():
    return MockTangoEventCallbackGroup(
        "files",
        "spead_data",
        "spead_headers",
    )


@pytest.fixture(name="device")
def fxt_device(pcap_dir: Path):
    with DeviceTestContext(
        PcapReader,
        properties={
            "pcap_dir": str(pcap_dir),
            "test_mode": TestMode.TEST.value,
        },
        process=True,
    ) as device:
        yield device


@pytest.mark.debug
def test_files_attribute_reacts_to_created_pcap_file(
    pcap_dir: Path,
    device: DeviceProxy,
    event_callbacks: MockTangoEventCallbackGroup,
):
    existing_files = device.files

    device.subscribe_event(
        "files",
        EventType.CHANGE_EVENT,
        event_callbacks["files"],
    )

    time.sleep(0.5)
    event_callbacks["files"].assert_change_event(existing_files)

    pcap_file = pcap_dir / "new_pcap_file.pcap"
    pcap_file.touch()
    time.sleep(0.5)

    assert pcap_file.name in json.loads(device.files)
    event_callbacks["files"].assert_change_event(device.files)

    pcap_file.unlink()
    time.sleep(0.5)

    assert pcap_file.name not in json.loads(device.files)
    event_callbacks["files"].assert_change_event(device.files)


def test_read_visibilities(
    device: DeviceProxy,
    event_callbacks: MockTangoEventCallbackGroup,
):
    expected_event_callbacks = ["spead_data", "spead_headers"]

    for attr_name in expected_event_callbacks:
        device.subscribe_event(attr_name, EventType.USER_EVENT, event_callbacks[attr_name])

    pcap_file_name = "existing_pcap_file.pcap"
    device.ReadVisibilityData(pcap_file_name)
    time.sleep(0.5)

    for attr_name in expected_event_callbacks:
        event_callbacks[attr_name].assert_change_event(
            (pcap_file_name, placeholders.Anything),
            lookahead=2,
        )
