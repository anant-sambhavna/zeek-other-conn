# zeek-other-conn

A Zeek package that logs the connections Zeek's core `conn.log` does **not**
record. Zeek's connection logging covers TCP, UDP and ICMP/ICMPv6. Everything
else is invisible in `conn.log`. This package fills that gap by aggregating:

* **Non-TCP/UDP/ICMP IP traffic** — any IP protocol number other than
  `1` (ICMP), `6` (TCP), `17` (UDP) and `58` (ICMPv6). For example GRE (47),
  ESP (50), AH (51), OSPF (89), SCTP (132), VRRP (112), and so on.
* **Pure L2 / non-IP Ethernet frames** — ARP, LLDP, STP, PROFINET, EtherCAT,
  and any other non-IP EtherType.

Frames are grouped into **bidirectional flows** (A→B and B→A collapse into one
record), accumulated over a flush interval, and written to `other_conn.log`.

## What it logs

`other_conn.log` reuses standard `conn.log` column naming where it is
meaningful, and adds L2 telemetry so no information is lost:

| Field | Meaning |
|-------|---------|
| `ts` | Flow start time |
| `uid` | Per-flow identifier (`OC-` prefix) |
| `id.orig_h` / `id.resp_h` | IP addresses (empty for pure-L2 frames) |
| `id.orig_p` / `id.resp_p` | Always `0` (no transport ports here) |
| `proto` | Context tag: `ip` or `non_ip` |
| `duration` | `last_seen - first_seen` |
| `orig_bytes` / `resp_bytes` | Bytes per direction |
| `orig_pkts` / `resp_pkts` | Packets per direction |
| `orig_ip_bytes` / `resp_ip_bytes` | Mirror of the byte counts |
| `orig_l2_addr` / `resp_l2_addr` | Source / destination MAC addresses |
| `vlan` | VLAN tag (`0` if untagged) |
| `eth_type` | EtherType value |
| `ip_proto` | Numeric L3 protocol (`255` = non-IP) |
| `first_seen` / `last_seen` | First and last frame timestamps |

L4-only `conn.log` fields (`service`, `conn_state`, `missed_bytes`, `history`,
`tunnel_parents`) are intentionally omitted — they are not derivable here.

## Requirements

* Zeek >= 5.0
* The script uses the `raw_packet` event, so Zeek must have access to the raw
  link layer (live capture or a pcap that includes L2 headers). It does not
  work on traces that start at the IP layer.

## Installation

```sh
zkg install https://github.com/anant-sambhavna/zeek-other-conn
```

Or from a local clone:

```sh
zkg install .
```

Then load it from your `local.zeek` (zkg does this automatically if you use
`@load packages`):

```
@load zeek-other-conn
```

## Configuration

All tunables are `&redef`-able:

```
# How often flows are flushed to the log (default 60s).
redef OtherConn::flush_interval = 30sec;

# Sentinel protocol number used for pure-L2 frames (default 255).
redef OtherConn::non_ip_proto = 255;
```

## Extending

An event hook fires immediately before each record is written, so other
scripts can observe or enrich flows:

```
event OtherConn::log_other_conn(rec: OtherConn::Info)
    {
    # inspect rec ...
    }
```

## License

BSD 3-Clause. See [COPYING](COPYING).
