# Use bash shell with pipefail option enabled so that the return status of a
# piped command is the value of the last (rightmost) command to exit with a
# non-zero status. This lets us pipe output into tee but still exit on test
# failures.
SHELL = /bin/bash
.SHELLFLAGS = -o pipefail -c

DOCS_SPHINXOPTS ?= -W

-include .make/base.mk
-include .make/python.mk

# Override base vars
PROJECT = ska-low-csp-testware
