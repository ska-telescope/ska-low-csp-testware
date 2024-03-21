# pylint: disable=missing-module-docstring,missing-function-docstring,missing-class-docstring

import logging

import pytest


@pytest.hookimpl
def pytest_configure(config: pytest.Config):
    config.addinivalue_line("markers", "debug: Enable debug logging")


@pytest.fixture(name="debug", autouse=True)
def fxt_debug(request: pytest.FixtureRequest, caplog: pytest.LogCaptureFixture):
    if request.node.get_closest_marker("debug"):
        caplog.set_level(logging.DEBUG)


@pytest.fixture(name="logger")
def fxt_logger():
    return logging.getLogger("ska_low_csp_testware")
