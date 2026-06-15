# E5 — Port Scanner Detector (eBPF/XDP)

## What it does
This project detects port scanning attacks using eBPF/XDP. It monitors incoming TCP SYN packets and blacklists any IP address that sends SYN packets to 15 or more different ports within a 10-second window.

## How it works
- XDP hook intercepts every incoming packet at the earliest point in the network stack
- TCP SYN packets are tracked per source IP using BPF maps
- A sliding window (10 seconds) counts unique destination ports per IP
- When threshold (15 ports) is exceeded, the IP is blacklisted
- All future packets from blacklisted IPs are dropped with XDP_DROP

## Files
- `common.h` — shared constants and structs between kernel and user space
- `e5_kern.bpf.c` — eBPF/XDP kernel program
- `e5_user.c` — user space monitor program
- `Makefile` — build configuration

## How to build
make
## How to run
sudo ./e5_user <interface>
Example:
sudo ./e5_user lo
## How to test
In a second terminal, run a port scan:
sudo nmap -sS -p 1-100 127.0.0.1
After 15 unique ports are scanned, the IP is blacklisted.
Run nmap again — all ports will show as filtered.

## Results
- Detected port scanner: 127.0.0.1 with 15 unique ports in 10 seconds
- After blacklisting: all 50 scanned ports filtered (XDP_DROP working)
## Containerlab Topology Test

A realistic three-node topology was tested using Containerlab:
hs1 (10.0.1.10) <---> rt1 (10.0.1.1/10.0.2.1) <---> hs2 (10.0.2.10)
attacker            eBPF running here                  target
### Deploy topology
```bash
cd containerlab
sudo containerlab deploy -t e5-topology.clab.yml
```

### Build and run on rt1
```bash
sudo docker exec -it clab-e5-lab-rt1 bash -c "cd /e5-port-scanner && make && ./e5_user eth1"
```

### Run port scan from hs1
```bash
sudo docker exec -it clab-e5-lab-hs1 nmap -sS -p 1-50 10.0.2.10
```

### Results
- hs1 (10.0.1.10) detected as scanner after 15 unique ports
- BLOCKED: 10.0.1.10 added to blacklist
- Second scan: All 50 scanned ports ignored (XDP_DROP confirmed)

### Destroy topology
```bash
sudo containerlab destroy -t e5-topology.clab.yml
```
