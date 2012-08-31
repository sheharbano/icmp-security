##! This script detects large number of ICMP Time Exceeded messages.
##! It generates a notice when the number of ICMP Time Exceeded 
##! messages for a source-destination pair exceeds threshold
@load base/frameworks/metrics

module ICMPTimeExceeded;

export {
	redef enum Notice::Type += {
		## Indicates that the number of ICMP Time Exceeded messages 
		## generated between a source-dest pair exceeded threshold
		ICMP_Time_Exceeded,
	};
	
	const id = "ICMP_TIME_EXCEEDED";
	
	## Defines the threshold for ICMP Time Exceeded messages for a src-dst pair
	const icmp_time_exceeded_threshold = 18 &redef;

	## Interval at which to watch for the
	## :bro:id:`ICMPTimeExceeded::icmp_time_exceeded_threshold` variable to be crossed.
	## At the end of each interval the counter is reset.
	const icmp_time_exceeded_interval = 5min &redef;

}

event bro_init() &priority=3
	{

	# Add filters to the metrics so that the metrics framework knows how to 
	# determine when it looks like an actual attack and how to respond when
	# thresholds are crossed.
	
	Metrics::add_filter(id, [$log=F,
	                                   $notice_threshold=icmp_time_exceeded_threshold,
	                                   $break_interval=icmp_time_exceeded_interval,
	                                   $note=ICMP_Time_Exceeded]);
	}



event icmp_time_exceeded(c: connection, icmp: icmp_conn, code: count, context: icmp_context)
	{
	local src_dst_pair = fmt("(src-%s)-->(dst-%s)",context$id$orig_h,context$id$resp_h);
	# This function does the following:
	# If index (src_dst_pair) doesn't exist, it creates an entry for this index. It
	# adds data (c$id$orig_h) to a set associated with this index. If the number
	# of unique data values for an index exceeds threshold, a notice is generated.
	# So the threshold applies to the number of unique data values associated with
	# an index.
	Metrics::add_unique(id,[ $str = src_dst_pair ], fmt("%s",c$id$orig_h));
	}







