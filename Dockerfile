FROM ubuntu:22.04

RUN apt-get update -qq && \
    apt-get install -y -qq build-essential cmake iptables iproute2 net-tools nmap netcat && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . /src

RUN mkdir -p /tmp/build && \
    cd /tmp/build && \
    cmake /src -DCMAKE_BUILD_TYPE=Release && \
    make -j$(nproc) && \
    cp /tmp/build/src/portspoof /usr/local/bin/portspoof && \
    rm -rf /tmp/build

EXPOSE 4444

ENTRYPOINT ["portspoof"]
