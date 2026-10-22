##! other-conn: log the connections that Zeek's core conn.log does not record.
##!
##! Scope:
##!   Aggregates every frame EXCEPT the protocols already covered by conn.log
##!   (TCP=6, UDP=17, ICMP=1, ICMPv6=58) into bidirectional flows and flushes
##!   them every ``OtherConn::flush_interval`` (default 60s). This captures:
##!     * non-TCP/UDP/ICMP IP traffic (any other IP protocol number), and
##!     * pure L2 / non-IP Ethernet frames.
##!
##! Output (other_conn.log):
##!   Uses standard conn.log column naming where meaningful (ts, uid,
##!   id.orig_h/p, id.resp_h/p, proto, duration, orig/resp bytes, orig/resp
##!   pkts, orig/resp ip_bytes) plus conn.log's L2 fields orig_l2_addr /
##!   resp_l2_addr, then appends vlan, eth_type, the numeric ip_proto and
##!   first_seen / last_seen so no telemetry is lost. L4-only conn.log fields
##!   (service, conn_state, missed_bytes, history, tunnel_parents) are omitted
##!   because they are not derivable here.

module OtherConn;

export {
    ## The other_conn logging stream identifier.
    redef enum Log::ID += { LOG };

    ## How often accumulated flows are written out and cleared.
    const flush_interval = 60sec &redef;

    ## Sentinel L3 protocol number used for pure L2 / non-IP frames.
    const non_ip_proto: count = 255 &redef;

    ## conn.log-style nested identifier. Ports are 0 for L2/non-IP frames.
    type OtherConnID: record {
        orig_h: string &log;   ##< orig IP (empty for pure-L2 frames)
        orig_p: count  &log;   ##< always 0 here (no transport port)
        resp_h: string &log;   ##< resp IP (empty for pure-L2 frames)
        resp_p: count  &log;   ##< always 0 here
    };

    type Info: record {
        # ---- conn.log core (fields meaningful here) ----
        ts:            time     &log;
        uid:           string   &log;
        id:            OtherConnID  &log;
        proto:         string   &log;  ##< "ip" / "ipv6" context tag, or "non_ip"
        duration:      interval &log;
        orig_bytes:    count    &log;
        resp_bytes:    count    &log;
        orig_pkts:     count    &log;
        orig_ip_bytes: count    &log;  ##< mirrors orig_bytes here
        resp_pkts:     count    &log;
        resp_ip_bytes: count    &log;  ##< mirrors resp_bytes here

        # ---- L2 telemetry (conn.log naming: orig_l2_addr / resp_l2_addr) ----
        orig_l2_addr: string &log;
        resp_l2_addr: string &log;
        vlan:         count  &log;
        eth_type:     count  &log;
        ip_proto:     count  &log;  ##< numeric L3 protocol (255 = non-IP)
        first_seen:   time   &log;
        last_seen:    time   &log;
    };

    ## Event fired just before a flow record is written. Allows other scripts
    ## to inspect or redef the record via a hook-style extension point.
    global log_other_conn: event(rec: Info);
}

type Flow: record {
    uid:        string;
    first_seen: time;
    last_seen:  time;

    orig_l2_addr: string;
    resp_l2_addr: string;
    orig_ip:    string;
    resp_ip:    string;

    vlan:       count;
    eth_type:   count;
    ip_proto:   count;

    orig_pkts:  count;
    resp_pkts:  count;
    orig_bytes: count;
    resp_bytes: count;
};

global flows: table[string] of Flow;
global uid_counter: count = 0;

function next_uid(): string
{
    ++uid_counter;
    return fmt("OC-%010d", uid_counter);
}

# Human-friendly protocol context tag for the conn.log-style `proto` column.
function proto_tag(ip_proto: count): string
{
    if ( ip_proto == non_ip_proto )
        return "non_ip";
    return "ip";
}

event flush_flows()
{
    local keys: vector of string = vector();

    for ( k in flows )
        {
        local f = flows[k];

        local rec: Info = [
            $ts=f$first_seen,
            $uid=f$uid,
            $id=[$orig_h=f$orig_ip, $orig_p=0, $resp_h=f$resp_ip, $resp_p=0],
            $proto=proto_tag(f$ip_proto),
            $duration=f$last_seen - f$first_seen,
            $orig_bytes=f$orig_bytes,
            $resp_bytes=f$resp_bytes,
            $orig_pkts=f$orig_pkts,
            $orig_ip_bytes=f$orig_bytes,
            $resp_pkts=f$resp_pkts,
            $resp_ip_bytes=f$resp_bytes,
            $orig_l2_addr=f$orig_l2_addr,
            $resp_l2_addr=f$resp_l2_addr,
            $vlan=f$vlan,
            $eth_type=f$eth_type,
            $ip_proto=f$ip_proto,
            $first_seen=f$first_seen,
            $last_seen=f$last_seen];

        event OtherConn::log_other_conn(rec);
        Log::write(LOG, rec);

        keys[|keys|] = k;
        }

    for ( i in keys )
        delete flows[keys[i]];

    schedule flush_interval { flush_flows() };
}

event zeek_init()
{
    Log::create_stream(LOG, [$columns=Info, $path="other_conn"]);
    schedule flush_interval { flush_flows() };
}

event raw_packet(p: raw_pkt_hdr)
{
    if ( ! p?$l2 )
        return;

    local vlan: count = 0;
    if ( p$l2?$vlan )
        vlan = p$l2$vlan;

    local sm = fmt("%s", p$l2$src);
    local dm = fmt("%s", p$l2$dst);

    local sip = "";
    local dip = "";
    local proto: count = non_ip_proto;

    if ( p?$ip )
        {
        proto = p$ip$p;
        # Skip protocols already covered by conn.log.
        if ( proto == 1 || proto == 6 || proto == 17 )
            return;

        sip = fmt("%s", p$ip$src);
        dip = fmt("%s", p$ip$dst);
        }
    else if ( p?$ip6 )
        {
        proto = p$ip6$nxt;
        # Skip protocols already covered by conn.log.
        if ( proto == 58 || proto == 6 || proto == 17 )
            return;

        sip = fmt("%s", p$ip6$src);
        dip = fmt("%s", p$ip6$dst);
        }

    # Canonicalize direction so A->B and B->A collapse into one flow.
    local forward = T;
    if ( sm > dm )
        forward = F;
    else if ( sm == dm && sip > dip )
        forward = F;

    local om  = forward ? sm  : dm;
    local rm  = forward ? dm  : sm;
    local oip = forward ? sip : dip;
    local rip = forward ? dip : sip;

    local key = fmt("%s|%s|%s|%s|%d|%d|%d",
                    om, rm, oip, rip, vlan, p$l2$eth_type, proto);

    if ( key !in flows )
        flows[key] =
            [$uid=next_uid(),
             $first_seen=network_time(),
             $last_seen=network_time(),
             $orig_l2_addr=om,
             $resp_l2_addr=rm,
             $orig_ip=oip,
             $resp_ip=rip,
             $vlan=vlan,
             $eth_type=p$l2$eth_type,
             $ip_proto=proto,
             $orig_pkts=0,
             $resp_pkts=0,
             $orig_bytes=0,
             $resp_bytes=0];

    flows[key]$last_seen = network_time();

    if ( forward )
        {
        ++flows[key]$orig_pkts;
        flows[key]$orig_bytes += p$l2$len;
        }
    else
        {
        ++flows[key]$resp_pkts;
        flows[key]$resp_bytes += p$l2$len;
        }
}
