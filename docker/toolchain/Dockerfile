FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        autoconf \
        automake \
        autotools-dev \
        bash \
        bc \
        bison \
        build-essential \
        ca-certificates \
        curl \
        device-tree-compiler \
        flex \
        gawk \
        git \
        gperf \
        libgmp-dev \
        libmpc-dev \
        libmpfr-dev \
        libtool \
        make \
        patch \
        python3 \
        texinfo \
        xz-utils \
        zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash builder \
    && mkdir -p /opt/riscv /opt/cva6-toolchain/src /opt/cva6-toolchain/build \
    && chown -R builder:builder /opt/riscv /opt/cva6-toolchain

USER builder
WORKDIR /workspace/rv-maltrace

ENV RISCV=/opt/riscv
ENV SRC_DIR=/opt/cva6-toolchain/src
ENV BUILD_DIR=/opt/cva6-toolchain/build
ENV NUM_JOBS=8

CMD ["/bin/bash"]
