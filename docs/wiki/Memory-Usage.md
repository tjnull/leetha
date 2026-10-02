# Memory usage and Linux swap

Leetha should shed packet work during a sustained burst instead of retaining
an ever-growing backlog. The capture status endpoint (`/api/capture/status`)
reports process RSS, processing queue depth and capacity, dropped packets, and
the size of the PCAP export buffer. A queue that remains near capacity while
drops increase means the capture rate exceeds the analysis rate. Inspect that
before raising the queue limit; a larger limit delays drops by using more RAM.

Linux, not Leetha, decides which memory pages to swap. Swap is a safety margin,
not a remedy for a producer that continuously outruns a consumer. Sustained
swap activity can make packet processing slower and grow the backlog faster.
Use `vmstat 1`, `free -h`, and `docker stats` to distinguish process RSS,
container memory use, and swap traffic. On cgroup v2 hosts, inspect
`memory.current`, `memory.swap.current`, `memory.events`, and
`memory.pressure` for the service's cgroup. The `si` and `so` columns in
`vmstat` show swap in and out rates.

For Docker, set a host-appropriate memory limit and an explicit swap allowance
in a Compose override. `memswap_limit` is **memory plus swap**, not just swap:

```yaml
services:
  leetha:
    mem_limit: 2g
    memswap_limit: 3g
```

For the systemd service, use a drop-in (`systemctl edit leetha.service`) with
limits chosen for the host:

```ini
[Service]
MemoryHigh=1G
MemoryMax=2G
MemorySwapMax=1G
```

`MemoryHigh` applies reclaim pressure before the hard `MemoryMax` limit.
Limits protect the host but can still cause Leetha to be killed if its working
set exceeds them. Test with your fingerprint feeds and normal sensor traffic
before selecting production values. If the queue is full, reduce sensor traffic
or capture interfaces; increasing swap or the queue size will not increase
the packet processing rate.

References: [Linux cgroup v2 memory controller](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html),
[Docker memory constraints](https://docs.docker.com/engine/containers/resource_constraints/),
[systemd resource control](https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html).
