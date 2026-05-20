FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        binutils-riscv64-unknown-elf \
        bc \
        bison \
        build-essential \
        ca-certificates \
        cpio \
        device-tree-compiler \
        file \
        flex \
        gcc-riscv64-unknown-elf \
        git \
        libssl-dev \
        make \
        meson \
        ninja-build \
        patch \
        perl \
        python3 \
        python3-packaging \
        python3-pip \
        python3-requests \
        python3-serial \
        python3-yaml \
        rsync \
        unzip \
        wget \
    && python3 -m pip install --break-system-packages --no-cache-dir \
        liteeth \
        pythondata-cpu-vexriscv \
        pythondata-software-compiler_rt \
    && git clone --depth 1 https://github.com/litex-hub/pythondata-software-picolibc.git /opt/pythondata-software-picolibc \
    && git -C /opt/pythondata-software-picolibc submodule update --init --recursive --depth 1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace/rv-maltrace

CMD ["/bin/bash"]
