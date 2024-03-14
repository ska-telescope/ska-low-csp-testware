# Use bash shell with pipefail option enabled so that the return status of a
# piped command is the value of the last (rightmost) command to exit with a
# non-zero status. This lets us pipe output into tee but still exit on test
# failures.
SHELL = /bin/bash
.SHELLFLAGS = -o pipefail -c

########################################################################
# BASE
########################################################################

include .make/base.mk

PROJECT = ska-low-csp-testware
DOCS_SPHINXOPTS ?= -W

########################################################################
# PYTHON
########################################################################

include .make/python.mk

PYTHON_LINE_LENGTH = 127

########################################################################
# HELM
########################################################################

include .make/helm.mk

########################################################################
# K8S
########################################################################

K8S_USE_HELMFILE = true
K8S_HELMFILE = helmfile.d/helmfile.yaml
K8S_HELMFILE_ENV ?= default

include .make/k8s.mk

########################################################################
# OCI
########################################################################

include .make/oci.mk

CI_JOB_ID ?= local
