FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

RUN apt-get update \
        -o Acquire::Retries=5 \
        -o Acquire::http::Timeout=30 \
        -o Acquire::https::Timeout=30 \
    && apt-get install -y --no-install-recommends \
        -o Acquire::Retries=5 \
        -o Acquire::http::Timeout=30 \
        -o Acquire::https::Timeout=30 \
        bash \
        binutils-riscv64-linux-gnu \
        bc \
        bpftrace \
        bison \
        build-essential \
        ca-certificates \
        clang \
        cpio \
        curl \
        file \
        flex \
        gawk \
        gcc \
        gcc-riscv64-linux-gnu \
        git \
        libncurses-dev \
        libssl-dev \
        libc6-dev-riscv64-cross \
        llvm \
        make \
        patch \
        perl \
        python3 \
        python3-pip \
        python3-venv \
        qemu-system-misc \
        qemu-user \
        rsync \
        strace \
        unzip \
        wget \
        xz-utils \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m pip install --break-system-packages --no-cache-dir uv

WORKDIR /workspace/rv-maltrace

CMD ["/bin/bash"]
