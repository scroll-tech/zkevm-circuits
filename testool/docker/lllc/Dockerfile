FROM alpine:3.15.6 AS build

WORKDIR /solidity

RUN apk update && apk add boost-dev boost-static build-base cmake git z3-dev

RUN git clone https://github.com/winsvega/lllc .
RUN git checkout 2b34e1d437bab8b92242262456fc922de86d0d30
COPY patch.diff patch.diff
RUN patch -p1 < patch.diff

WORKDIR /solidity/build
RUN cmake .. -DCMAKE_BUILD_TYPE=Release -DLLL=1
RUN make -j2

ENTRYPOINT ["/solidity/build/lllc/lllc"]
