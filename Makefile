# Use bash shell with pipefail option enabled so that the return status of a
# piped command is the value of the last (rightmost) command to exit with a
# non-zero status. This lets us pipe output into tee but still exit on test
# failures.
SHELL = /bin/bash
.SHELLFLAGS = -o pipefail -c

DOCS_SPHINXOPTS ?= -W

# Override base vars
PROJECT = ska-low-csp-testware

# Override vars for python targets
PYTHON_LINE_LENGTH = 127

K8S_CHART ?= test-parent
K8S_CHARTS = $(K8S_CHART)
K8S_UMBRELLA_CHART_PATH ?= charts/test-parent/
HELM_CHARTS_TO_PUBLISH = $(PROJECT)
HELM_CHARTS ?= $(HELM_CHARTS_TO_PUBLISH)


-include .make/base.mk
-include .make/python.mk
-include .make/k8s.mk
-include .make/helm.mk
-include .make/oci.mk

CI_JOB_ID ?= local
