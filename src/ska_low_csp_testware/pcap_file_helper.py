"""
Entrypoint for the ``pcap_file_helper`` TANGO device server.
"""

from tango.server import run

from ska_low_csp_testware.pcap_file_device import PcapFile
from ska_low_csp_testware.pcap_file_watcher_device import PcapFileWatcher


def main(args=None, **kwargs):  # pylint: disable=missing-function-docstring
    return run((PcapFileWatcher, PcapFile), args=args, **kwargs)


if __name__ == "__main__":
    main()
