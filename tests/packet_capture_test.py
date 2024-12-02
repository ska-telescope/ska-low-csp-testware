# pylint: disable=missing-module-docstring
# pylint: disable=missing-function-docstring
# pylint: disable=missing-class-docstring

import pytest
from tango import DeviceProxy, DevState
from tango.test_context import DeviceTestContext

from ska_low_csp_testware.packet_capture import PacketCapture

pytestmark = pytest.mark.forked


@pytest.fixture(name="device")
def fxt_device():
    with DeviceTestContext(
        PacketCapture,
        properties={"interface": "eth0", "port": 9999, "output_dir": "/tmp"},
        process=True,
    ) as device:
        yield device


def test_device_inits_ok(device: DeviceProxy):
    assert device.State() == DevState.ON
