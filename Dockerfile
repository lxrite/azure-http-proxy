FROM ubuntu:22.04 as builder

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

RUN apt-get update \
    && apt-get install -yq gcc g++ make cmake libssl-dev

WORKDIR /ahp

COPY . .

RUN cmake -B build -DCMAKE_BUILD_TYPE=Release \
    && cmake --build build

FROM ubuntu:22.04

COPY --from=builder /ahp/build/ahps /usr/local/bin/ahps
COPY --from=builder /ahp/build/ahpc /usr/local/bin/ahpc
