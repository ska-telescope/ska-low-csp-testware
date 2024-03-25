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


@pytest.fixture(name="existing_pcap_file_name")
def fxt_existing_pcap_file_name():
    return "existing_pcap_file.pcap"


@pytest.fixture(name="pcap_dir")
def fxt_pcap_dir(tmp_path: Path, existing_pcap_file_name: str):
    tmp_path.joinpath(existing_pcap_file_name).touch()
    return tmp_path


@pytest.fixture(name="event_callbacks")
def fxt_event_callbacks():
    return MockTangoEventCallbackGroup(
        "file_name_mapping",
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


def test_files_attribute_contains_existing_files_after_init(
    device: DeviceProxy,
    existing_pcap_file_name: str,
):
    assert existing_pcap_file_name in json.loads(device.file_name_mapping)


def test_dynamic_attributes_are_created_for_existing_files_after_init(
    device: DeviceProxy,
    existing_pcap_file_name: str,
):
    attr_prefix = json.loads(device.file_name_mapping)[existing_pcap_file_name]
    assert f"{attr_prefix}_data" in device.get_attribute_list()
    assert f"{attr_prefix}_info" in device.get_attribute_list()


def test_files_attribute_does_not_contain_file_when_deleted(
    device: DeviceProxy,
    pcap_dir: Path,
    existing_pcap_file_name: str,
):
    file = pcap_dir.joinpath(existing_pcap_file_name)
    file.unlink()
    time.sleep(0.5)

    assert existing_pcap_file_name not in json.loads(device.file_name_mapping)


def test_dynamic_attributes_are_removed_when_file_is_deleted(
    device: DeviceProxy,
    pcap_dir: Path,
    existing_pcap_file_name: str,
):
    attr_prefix = json.loads(device.file_name_mapping)[existing_pcap_file_name]

    file = pcap_dir.joinpath(existing_pcap_file_name)
    file.unlink()
    time.sleep(0.5)

    assert f"{attr_prefix}_data" not in device.get_attribute_list()
    assert f"{attr_prefix}_info" not in device.get_attribute_list()


def test_files_attribute_reacts_to_created_pcap_file(
    pcap_dir: Path,
    device: DeviceProxy,
    event_callbacks: MockTangoEventCallbackGroup,
):
    existing_files = device.file_name_mapping

    device.subscribe_event(
        "file_name_mapping",
        EventType.CHANGE_EVENT,
        event_callbacks["file_name_mapping"],
    )

    time.sleep(0.5)
    event_callbacks["file_name_mapping"].assert_change_event(existing_files)

    pcap_file = pcap_dir / "new_pcap_file.pcap"
    pcap_file.touch()
    time.sleep(0.5)

    assert pcap_file.name in json.loads(device.file_name_mapping)
    event_callbacks["file_name_mapping"].assert_change_event(device.file_name_mapping)

    pcap_file.unlink()
    time.sleep(0.5)

    assert pcap_file.name not in json.loads(device.file_name_mapping)
    event_callbacks["file_name_mapping"].assert_change_event(device.file_name_mapping)


@pytest.mark.debug
def test_read_visibilities(
    device: DeviceProxy,
    existing_pcap_file_name: str,
):
    attr_prefix = json.loads(device.file_name_mapping)[existing_pcap_file_name]
    attr_name = f"{attr_prefix}_data"
    callbacks = MockTangoEventCallbackGroup(attr_name)
    device.subscribe_event(attr_name, EventType.CHANGE_EVENT, callbacks[attr_name])
    time.sleep(0.5)
    callbacks[attr_name].assert_change_event(None)

    device.ReadVisibilityData(existing_pcap_file_name)
    time.sleep(0.5)

    callbacks[attr_name].assert_change_event(placeholders.Anything)
