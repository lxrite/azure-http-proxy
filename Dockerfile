FROM ubuntu:20.04

ARG DEBIAN_FRONTEND=noninteractive

ENV TZ=UTC

RUN apt update \
    && apt install -yq gcc g++ make cmake libssl-dev

WORKDIR /ahp

ADD . .

RUN cmake -B build -DCMAKE_BUILD_TYPE=Release \
    && cmake --build build \
    && cp /ahp/build/ahps /usr/bin \
    && cp /ahp/build/ahpc /usr/bin
