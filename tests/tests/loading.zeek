# @TEST-DOC: The package loads cleanly and creates the other_conn stream.
#
# @TEST-EXEC: zeek -b %DIR/../../scripts/__load__.zeek %INPUT >output 2>&1
# @TEST-EXEC: btest-diff output

event zeek_init() &priority=-10
    {
    # If the stream was created by the package, this returns a valid filter.
    local f = Log::get_filter(OtherConn::LOG, "default");
    print fmt("stream_created=%s", f$name == "default");
    print fmt("flush_interval=%s", OtherConn::flush_interval);
    print fmt("non_ip_proto=%s", OtherConn::non_ip_proto);
    }
