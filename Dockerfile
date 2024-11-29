ARG BUILD_IMAGE="artefact.skao.int/ska-tango-images-pytango-builder:9.5.0"
ARG BASE_IMAGE="artefact.skao.int/ska-tango-images-pytango-runtime:9.5.0"
ARG POETRY_VERSION=1.8.4

FROM $BUILD_IMAGE AS buildenv
FROM $BASE_IMAGE

USER root

RUN poetry self update "${POETRY_VERSION}"

RUN apt-get update && apt-get install git tcpdump python3-dev g++ -y

RUN poetry config virtualenvs.create false

RUN poetry install --only main

USER tango
