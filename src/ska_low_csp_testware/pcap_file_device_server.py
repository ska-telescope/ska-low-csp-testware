# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,broad-exception-caught

from tango.server import run

from ska_low_csp_testware.pcap_file_device import PcapFileDevice
from ska_low_csp_testware.pcap_file_watcher_device import PcapFileWatcherDevice


def main(args=None, **kwargs):
    return run((PcapFileWatcherDevice, PcapFileDevice), args=args, **kwargs)


if __name__ == "__main__":
    main()
