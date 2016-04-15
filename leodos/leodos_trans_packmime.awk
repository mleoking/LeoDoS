BEGIN {
	f_out="./result/leodos_packmime.tr";
} 
function output(o_event,o_time,o_fromnode,o_tonode,o_pkttype,o_pktsize,o_flags,o_fid,o_srcaddr,o_dstaddr,o_seqnum,o_pktid){
	printf "%s ", o_event >> f_out;
	printf "%s ", o_time >> f_out;
	printf "%s ", o_fromnode >> f_out;
	printf "%s ", o_tonode >> f_out;
	printf "%s ", o_pkttype >> f_out;
	printf "%s ", o_pktsize >> f_out;
	printf "%s ", o_flags >> f_out;
	printf "%s ", o_fid >> f_out;
	printf "%s ", o_srcaddr >> f_out;
	printf "%s ", o_dstaddr >> f_out;
	printf "%s ", o_seqnum >> f_out;
	printf "%s ", o_pktid >> f_out;
	printf "\n" >> f_out;
}
{
	event = $1;
 	time = $2;
 	fromnode = $3;
 	tonode = $4;
	pkttype = $5;
 	pktsize = $6;
	flags = $7;
 	fid = $8;
 	srcaddr = $9;
	dstaddr = $10;
	seqnum = $11;
	pktid = $12;	

	o_event = event;
 	o_time = time;
 	o_fromnode = fromnode;
 	o_tonode = tonode;
	o_pkttype = pkttype;
 	o_pktsize = pktsize;
	o_flags = flags
 	o_fid = fid;
 	o_srcaddr = srcaddr;
	o_dstaddr = dstaddr;
	o_seqnum = seqnum;
	o_pktid = pktid;

	if ( pkttype=="tcp" || pkttype=="ack"){
		o_fid=1;
	}
	sub(/\.[0-9]*/,".0",o_srcaddr);
	sub(/\.[0-9]*/,".0",o_dstaddr);
	output(o_event,o_time,o_fromnode,o_tonode,o_pkttype,o_pktsize,o_flags,o_fid,o_srcaddr,o_dstaddr,o_seqnum,o_pktid);
}						  
END {
}
