module GOOSE;

global goose_topic = "/topic/goose";

global begin_time: time;
global total_time: interval;

export {
	## Log stream identifier.
	redef enum Log::ID += { GOOSE_LOG };

	## Record type containing the column fields of the goose log.
	type Info: record {
		## Timestamp for when the activity happened.
		ts: time &log &default=network_time();
        #	appid: count &log &optional;
        #	pkt_len: count &log &optional;
		payload: string &optional &log;
	};

    	#global GOOSE::message: event(pkt: raw_pkt_hdr, appid: count, pkt_len: count);
    	global GOOSE::message: event(pkt: raw_pkt_hdr, payload: string);

    	global GOOSE::log_goose: event(rec: GOOSE::Info);

	#global log_GOOSE: event(rec: Info);
}

redef record raw_pkt_hdr  += {
	GOOSE: Info &optional;
};


event zeek_init()
	{

	 if ( ! PacketAnalyzer::try_register_packet_analyzer_by_name("Ethernet", 0x88ba, "spicy_GOOSE") )
 	       if ( ! PacketAnalyzer::try_register_packet_analyzer_by_name("Ethernet", 0x88ba, "spicy::GOOSE") )
		    print "cannot register GOOSE Spicy analyzer";

	#Broker::peer(addr_to_uri(127.0.0.1), 50001/tcp);

    	#Log::create_stream(GOOSE::GOOSE_LOG, [$columns=Info, $ev=log_goose, $path="goose"]);
	}


# Example event defined in GOOSE.evt.
#event GOOSE::message(packet: raw_pkt_hdr, appid: count, pkt_len: count)
event GOOSE::message(packet: raw_pkt_hdr, payload: string)
 	{

	#local info: Info = [$ts=network_time(), $appid=appid, $pkt_len=pkt_len];
	local info: Info = [$ts=network_time(), $payload=payload];
        print "Processing pcakets", info;
	Log::write(GOOSE::GOOSE_LOG, info);
 	}

event zeek_init() &priority=5
    {
    Log::create_stream(GOOSE::GOOSE_LOG, [$columns=Info, $ev=log_goose, $path="goose"]);
    }

