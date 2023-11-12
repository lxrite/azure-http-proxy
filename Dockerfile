FROM alpine:3.18 as builder

RUN apk update \
    && apk add alpine-sdk cmake openssl-dev linux-headers

WORKDIR /ahp

COPY . .

RUN cmake -B build -DCMAKE_BUILD_TYPE=Release \
    && cmake --build build

FROM alpine:3.18

RUN apk update && apk add libgcc libstdc++ openssl

COPY --from=builder /ahp/build/ahps /usr/local/bin/ahps
COPY --from=builder /ahp/build/ahpc /usr/local/bin/ahpc
