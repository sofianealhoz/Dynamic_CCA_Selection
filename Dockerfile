# syntax=docker/dockerfile:1
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-venv python3-pip \
    python3-bpfcc bpfcc-tools libbpf-dev libelf-dev clang llvm gcc make pkg-config \
    iproute2 iperf3 sudo git ca-certificates \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app    return await HardDriveService().get_harddrive_usage(request.app.state.monitortask)

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p samples/bpf \
  && clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -c tcp_changecc_kern.c -o samples/bpf/tcp_changecc_kern.o \
  && gcc load_sock_ops.c -o samples/bpf/load_sock_ops -lbpf -lelf

COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["python3", "event_listener.py", "c", "5", "cubic", "wi-fi"]
