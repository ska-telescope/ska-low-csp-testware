ARG BUILD_IMAGE="artefact.skao.int/ska-tango-images-pytango-builder:9.5.0"
ARG BASE_IMAGE="artefact.skao.int/ska-tango-images-pytango-runtime:9.5.0"
FROM $BUILD_IMAGE AS buildenv
FROM $BASE_IMAGE

USER root

RUN apt-get update && apt-get install git tcpdump python3-dev g++ -y

RUN poetry config virtualenvs.create false

RUN poetry install --only main

USER tango
