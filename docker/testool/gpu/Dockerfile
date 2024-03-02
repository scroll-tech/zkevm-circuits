FROM scrolltech/cuda-go-rust-builder:cuda-11.7.1-go-1.19-rust-nightly-2022-12-10 as builder

ARG TESTOOL_FEATURE=inner-prove
ENV LD_LIBRARY_PATH /usr/local/cuda/lib64:$LD_LIBRARY_PATH
WORKDIR /src
ADD . /src
RUN mkdir /.cargo && echo 'paths = ["/src/halo2-gpu/halo2_proofs"]' > /.cargo/config
RUN cargo build --features $TESTOOL_FEATURE --release
Run cd ./target/release && find -name libzktrie.so | xargs -I {} cp {} ./
RUN apt update && apt install -y curl
RUN mkdir test_assets
RUN curl -o ./test_assets/layer1.config https://circuit-release.s3.us-west-2.amazonaws.com/release-v0.9.5/layer1.config
RUN curl -o ./test_assets/layer2.config https://circuit-release.s3.us-west-2.amazonaws.com/release-v0.9.5/layer2.config

FROM nvidia/cuda:11.7.1-runtime-ubuntu22.04

ENV LD_LIBRARY_PATH /usr/local/cuda/lib64:$LD_LIBRARY_PATH
ENV SCROLL_PROVER_ASSETS_DIR /opt/test_assets
ENV SCROLL_PROVER_PARAMS_DIR /opt/test_params
ENV RUST_MIN_STACK 100000000
ENV RUST_BACKTRACE 1
ENV RUST_LOG info
WORKDIR /opt
RUN apt update && apt install -y git
RUN mkdir -p /opt/configs /opt/report /opt/tests
COPY --from=builder /src/target/release/libzktrie.so /usr/local/lib/
COPY --from=builder /src/target/release/testool /bin/
COPY --from=builder /src/test_assets/ /opt/test_assets/
COPY --from=builder /src/testool/tests/ /opt/tests/
COPY --from=builder /src/testool/Config.toml /opt/
COPY --from=builder /src/testool/codehash.txt /opt/
COPY --from=builder /src/testool/test_ids.txt /opt/
COPY --from=builder /src/testool/run_in_docker.sh /opt/run_testool.sh
