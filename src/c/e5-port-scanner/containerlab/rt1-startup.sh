#!/bin/sh

# Network setup
sysctl -w net.ipv4.ip_forward=1
ip addr add 10.0.1.1/24 dev eth1
ip addr add 10.0.2.1/24 dev eth2

# Install dependencies
apt-get update -qq
apt-get install -y -qq clang llvm libelf-dev libbpf-dev iproute2

# Run E5 port scanner detector on eth1
cd /e5-port-scanner
make
./e5_user eth1 &

