"""
Module containing shared pytest fixtures.
"""

import logging

import pytest


@pytest.hookimpl
def pytest_configure(config: pytest.Config):
    """
    Pytest hook to add configuration used by this module.
    """
    config.addinivalue_line("markers", "debug(*loggers): Enable debug logging")


@pytest.fixture(name="debug", autouse=True)
def fxt_debug(request: pytest.FixtureRequest, caplog: pytest.LogCaptureFixture):
    """
    Fixture that configures pytest in debug mode when ``pytest.mark.debug`` is used.
    """
    if mark := request.node.get_closest_marker("debug"):
        for logger in mark.args or [None]:
            caplog.set_level(logging.DEBUG, logger=logger)


@pytest.fixture(name="logger")
def fxt_logger():
    """
    Fixture that returns a ``logging.Logger`` instance.
    """
    return logging.getLogger("ska_low_csp_testware")
