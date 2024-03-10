# pylint: disable=missing-module-docstring,missing-function-docstring

import pytest
from tango.test_context import MultiDeviceTestContext

from ska_low_csp_testware.dynamic_device import Child, Parent

devices_info = (
    {
        "class": Parent,
        "devices": [
            {"name": "test/parent/0"},
        ],
    },
    {
        "class": Child,
        "devices": [],
    },
)


@pytest.fixture(name="context")
def fxt_context():
    with MultiDeviceTestContext(devices_info, process=True) as context:
        yield context


def test_spawn(context):
    parent = context.get_device("test/parent/0")
    parent.spawn()
