FROM 52a5259e139b807a9bcfd42109e269a6eedbfdbe69e52c6fdd42c0010a0768c7
USER 0
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 iptables && rm -rf /var/lib/apt/lists/*
RUN rustc --version && cargo --version && ip -Version && iptables --version
LABEL io.cmtc.purpose="Rust 1.90 ARM64 privileged namespace qualification"
