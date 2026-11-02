FROM python:3.10

RUN apt-get update && apt-get install -y --no-install-recommends \
        git protobuf-compiler openjdk-21-jdk \
        curl build-essential pkg-config \
        ninja-build cmake flex bison \
        libglib2.0-dev libpixman-1-dev libslirp-dev \
        clang libclang-dev llvm-dev \
    && rm -rf /var/lib/apt/lists/*

# Java: symlink arch independent (amd64/arm64)
RUN ln -s "$(dirname "$(dirname "$(readlink -f "$(which javac)")")")" /opt/java
ENV JAVA_HOME=/opt/java
ENV PATH="${JAVA_HOME}/bin:${PATH}"

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir "protobuf==5.28.2" \
    && pip install --no-cache-dir -r /tmp/requirements.txt \
    && pip install --no-cache-dir pyghidra

# QEMU (libafl_qemu) Python dependencies
RUN /usr/local/bin/python3 -m pip install --no-cache-dir \
        distlib setuptools wheel tomli \
    && /usr/local/bin/python3 -c "import distlib, tomli; print('deps OK')"

# --- User dev with the same UID/GID of the host ---
ARG UID=1000
ARG GID=1000

RUN groupadd -o -g ${GID} dev \
    && useradd -o -m -u ${UID} -g ${GID} -s /bin/bash dev \
    && mkdir -p /opt/rust \
    && chown dev:dev /opt/rust

USER dev
ENV HOME=/home/dev

ENV RUSTUP_HOME=/opt/rust/rustup \
    CARGO_HOME=/opt/rust/cargo
ENV PATH="${CARGO_HOME}/bin:${PATH}"
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path

WORKDIR /goldrush

ENV GHIDRA_INSTALL_DIR=/goldrush/ghidra_12.1.3_PUBLIC_20260817/ghidra_12.1.3_PUBLIC
