#!/bin/bash
set -euo pipefail

mkdir -p /app/samples/bpf
mkdir -p /tmp/cgroupv2

if ! mountpoint -q /tmp/cgroupv2; then
  mount -t cgroup2 none /tmp/cgroupv2
fi

mkdir -p /tmp/cgroupv2/foo

if [ -w /tmp/cgroupv2/foo/cgroup.procs ]; then
  echo $$ >> /tmp/cgroupv2/foo/cgroup.procs
fi

samples/bpf/load_sock_ops -l /tmp/cgroupv2/foo samples/bpf/tcp_changecc_kern.o &

cleanup() {
  jobs -p | xargs -r kill
}
trap cleanup EXIT

exec "$@"
