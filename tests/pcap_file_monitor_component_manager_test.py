"""
Unit tests for the :py:class:`ska_low_csp_testware.pcap_file_monitor_device.PcapFileMonitorComponentManager`.
"""

import logging
import time
from pathlib import Path

import pytest
from ska_control_model import CommunicationStatus, PowerState
from ska_tango_testing.mock import MockCallableGroup

from ska_low_csp_testware.pcap_file_monitor_device import PcapFileMonitorComponentManager

POLL_RATE = 0.1


@pytest.fixture(name="component_manager")
def fxt_component_manager(
    tmp_path: Path,
    logger: logging.Logger,
    callbacks: MockCallableGroup,
):
    """
    Fixture that yields a new :py:class:`PcapFileMonitorComponentManager` and turns it on.
    Any callback invocations that happen as a result of this action are consumed from the :py:class:`MockCallableGroup`.
    """
    component_manager = PcapFileMonitorComponentManager(
        pcap_dir=tmp_path,
        logger=logger,
        communication_state_callback=callbacks["communication_state"],
        component_state_callback=callbacks["component_state"],
        poll_rate=POLL_RATE,
        files=[],
    )

    component_manager.start_communicating()
    callbacks["communication_state"].assert_call(
        CommunicationStatus.ESTABLISHED,
        lookahead=2,
        consume_nonmatches=True,
    )
    callbacks["component_state"].assert_call(
        power=PowerState.ON,
        fault=False,
    )
    yield component_manager
    component_manager.stop_communicating()


@pytest.mark.usefixtures("component_manager")
@pytest.mark.debug
def test_component_state_changes_on_new_pcap_file(
    tmp_path: Path,
    callbacks: MockCallableGroup,
):
    """
    Test that checks that component state changes are triggered when a PCAP file is created.
    """
    pcap_file_path = tmp_path / "sample_file.pcap"
    pcap_file_path.touch()
    time.sleep(POLL_RATE)

    callbacks["component_state"].assert_call(files=[pcap_file_path])


@pytest.mark.usefixtures("component_manager")
def test_no_component_state_change_on_new_txt_file(
    tmp_path: Path,
    callbacks: MockCallableGroup,
):
    """
    Test that checks that component state changes are not triggered when a non-PCAP file is created.
    """
    txt_file_path = tmp_path / "sample_file.txt"
    txt_file_path.touch()
    time.sleep(POLL_RATE)

    callbacks["component_state"].assert_not_called()


@pytest.mark.usefixtures("component_manager")
def test_no_component_state_change_on_nested_pcap_file(
    tmp_path: Path,
    callbacks: MockCallableGroup,
):
    """
    Test that checks that component state changes are not triggered when a PCAP file is created in a subdirectory.
    """
    subdir_path = tmp_path / "nested"
    subdir_path.mkdir()
    pcap_file_path = subdir_path / "sample_file.pcap"
    pcap_file_path.touch()
    time.sleep(POLL_RATE)

    callbacks["component_state"].assert_not_called()


@pytest.mark.usefixtures("component_manager")
def test_component_state_changes_on_removed_pcap_file(
    tmp_path: Path,
    callbacks: MockCallableGroup,
):
    """
    Test that checks that component state changes are triggered when a PCAP file is removed.
    """
    pcap_file_path = tmp_path / "sample_file.pcap"
    pcap_file_path.touch()
    time.sleep(POLL_RATE)

    pcap_file_path.unlink()
    time.sleep(POLL_RATE)

    callbacks["component_state"].assert_call(files=[], lookahead=2)


@pytest.mark.usefixtures("component_manager")
def test_no_component_state_change_on_removed_txt_file(
    tmp_path: Path,
    callbacks: MockCallableGroup,
):
    """
    Test that checks that component state changes are not triggered when a non-PCAP file is removed.
    """
    txt_file_path = tmp_path / "sample_file.txt"
    txt_file_path.touch()
    time.sleep(POLL_RATE)

    txt_file_path.unlink()
    time.sleep(POLL_RATE)

    callbacks["component_state"].assert_not_called()


def test_no_component_state_changes_when_offline(
    component_manager: PcapFileMonitorComponentManager,
    tmp_path: Path,
    callbacks: MockCallableGroup,
):
    """
    Test that checks that component state changes are not triggered if the component manager is offline.
    """
    component_manager.stop_communicating()
    time.sleep(POLL_RATE)
    callbacks["component_state"].assert_against_call(power=PowerState.UNKNOWN)

    pcap_file_path = tmp_path / "sample_file.pcap"
    pcap_file_path.touch()
    time.sleep(POLL_RATE)

    pcap_file_path.unlink()
    time.sleep(POLL_RATE)

    callbacks["component_state"].assert_not_called()
