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
        build-essential \
        ca-certificates \
        gcc-riscv64-linux-gnu \
        libc6-dev-riscv64-cross \
        git \
        make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace/rv-maltrace

CMD ["/bin/bash"]
