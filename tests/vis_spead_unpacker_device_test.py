# pylint: disable=missing-module-docstring,missing-function-docstring
import io
import time

import pandas
import pytest
from tango import DeviceProxy
from tango.test_context import DeviceTestContext

from ska_low_csp_testware.vis_spead_unpacker_device import VisSpeadUnpacker


@pytest.fixture(name="device")
def fxt_device():
    with DeviceTestContext(VisSpeadUnpacker, properties={"pcap_dir": "tests"}) as proxy:
        yield proxy


@pytest.mark.timeout(30)
def test_unpack_metadata(device: DeviceProxy):
    device.set_timeout_millis(10_000)
    identifier = device.Unpack("vis.pcap")
    metadata_attr = f"{identifier}_metadata"
    while metadata_attr not in device.get_attribute_list():
        time.sleep(2)

    metadata_json = device.read_attribute(metadata_attr).value
    metadata = pandas.read_json(io.StringIO(metadata_json))
    assert metadata.at[0, "Basel"] == 21  # pylint: disable=no-member
