FROM ubuntu:20.04

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
  && apt-get install -y --no-install-recommends build-essential cmake libelf-dev binutils procps gdb \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .
RUN cmake -S . -B build && cmake --build build

WORKDIR /src/bin
CMD ["bash"]
