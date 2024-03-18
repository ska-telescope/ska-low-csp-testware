"""
Unit tests for the :py:class:`ska_low_csp_testware.pcap_file_device.PcapFileComponentManager`.
"""

import logging
import time
from pathlib import Path

import pytest
from ska_control_model import CommunicationStatus, PowerState
from ska_tango_testing.mock import MockCallableGroup, placeholders

from ska_low_csp_testware import pcap_file_device
from ska_low_csp_testware.common_types import DataType
from ska_low_csp_testware.pcap_file_device import PcapFileComponentManager

POLL_RATE = 0.1


@pytest.fixture(name="pcap_file")
def fxt_pcap_file(tmp_path: Path):
    """
    Fixture that creates a sample PCAP file to pass to the component manager.
    """
    pcap_file = tmp_path / "sample_file.pcap"
    pcap_file.touch()
    return pcap_file


@pytest.fixture(name="component_manager")
def fxt_component_manager(
    pcap_file: Path,
    logger: logging.Logger,
    callbacks: MockCallableGroup,
):
    """
    Fixture that yields a new :py:class:`PcapFileComponentManager` and turns it on.
    Any callback invocations that happen as a result of this action are consumed from the :py:class:`MockCallableGroup`.
    """
    component_manager = PcapFileComponentManager(
        pcap_file_path=pcap_file,
        logger=logger,
        communication_state_callback=callbacks["communication_state"],
        component_state_callback=callbacks["component_state"],
        poll_rate=POLL_RATE,
        file_contents=None,
        file_time_modified=pcap_file.stat().st_mtime_ns,
        file_size=pcap_file.stat().st_size,
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
def test_component_state_changes_when_file_changes(
    pcap_file: Path,
    callbacks: MockCallableGroup,
):
    """
    Test that checks that component state changes are triggered when the PCAP file is updated.
    """
    time.sleep(POLL_RATE)  # Forces the file mtime to change

    with pcap_file.open("w", encoding="utf8") as writer:
        writer.write("Hello, World!")

    time.sleep(POLL_RATE)

    callbacks["component_state"].assert_call(
        file_time_modified=placeholders.Anything,
        file_size=placeholders.Anything,
    )


@pytest.mark.usefixtures("component_manager")
def test_communication_state_changes_when_file_is_removed(
    pcap_file: Path,
    callbacks: MockCallableGroup,
):
    """
    Test that checks that communication state changes are triggered when the PCAP file no longer exists.
    """
    pcap_file.unlink()
    time.sleep(POLL_RATE)
    callbacks["communication_state"].assert_call(CommunicationStatus.NOT_ESTABLISHED)


def test_delete_file(
    pcap_file: Path,
    component_manager: PcapFileComponentManager,
):
    """
    Test that checks that the component manager's ``delete`` method deletes the PCAP file from disk.
    """
    component_manager.delete()
    assert not pcap_file.exists()


def test_communication_state_changes_when_calling_delete_command(
    component_manager: PcapFileComponentManager,
    callbacks: MockCallableGroup,
):
    """
    Test that checks that the component manager turns itself off after deleting the PCAP file.
    """
    component_manager.delete()
    time.sleep(POLL_RATE)
    callbacks["communication_state"].assert_call(CommunicationStatus.DISABLED)


def test_component_state_changes_when_loading_file_contents(
    component_manager: PcapFileComponentManager,
    callbacks: MockCallableGroup,
    monkeypatch: pytest.MonkeyPatch,
):
    """
    Test that checks that the component state is updated with the PCAP file contents when the ``load`` method is called.
    """

    def mocktask(**kwargs):
        result_callback = kwargs.get("result_callback", None)

        def _call(**kwargs):  # pylint: disable=unused-argument
            if result_callback:
                result_callback(42)

        return _call

    monkeypatch.setattr(pcap_file_device, "ReadLowCbfVisibilitiesTask", mocktask)
    component_manager.load(DataType.VIS)
    callbacks["component_state"].assert_call(file_contents=42)
