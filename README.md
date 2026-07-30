````markdown
# XDP Firewall

A simple XDP/eBPF firewall that blocks packets based on the source IPv4 address using a BPF hash map.

## Requirements

- Linux kernel with XDP and eBPF support
- clang
- libbpf
- bpftool
- make

## Build

Compile the project:

```bash
make
```

This generates:

- `firewall.bpf.o` – XDP/eBPF program
- `user_app` – Userspace utility to manage blocked IP addresses

## Load the eBPF Program

Load the XDP program:

```bash
sudo bpftool prog load firewall.bpf.o /sys/fs/bpf/firewall
```

## Attach to an Interface

Replace `<INTERFACE>` with your network interface (for example `eth0` or `ens33`).

```bash
sudo bpftool net attach xdp pinned /sys/fs/bpf/firewall dev <INTERFACE>
```

## Verify

Check that the program is attached:

```bash
ip -details link show <INTERFACE>
```

## Manage Blocked IP Addresses

The userspace application is used only to manage entries in the pinned BPF map.

### Add an IP address

```bash
sudo ./user_app add 192.168.1.100
```

### Remove an IP address

```bash
sudo ./user_app remove 192.168.1.100
```

### List blocked IPs

```bash
sudo bpftool map dump pinned /sys/fs/bpf/ip_block_map
```

## View Debug Messages

If `bpf_printk()` is used:

```bash
sudo cat /sys/kernel/tracing/trace_pipe
```

or on older kernels:

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

## Detach the XDP Program

```bash
sudo ip link set dev <INTERFACE> xdp off
```

## Clean

```bash
make clean
```
````

