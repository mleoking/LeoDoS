BEGIN {
	if (dt=="") {
		dt=0.01; #second
	}	
	if (s_l=="") {
		s_l=dt; #sample length is 1s.
	}
	if (t_st=="") {
		t_st=25;#calculate from 25 second
	}
	if (t_sp=="") {
		t_sp=215;#calculate to 215 second
	}
	if (p_ct=="") {
		p_ct="pktcount";
	}

	f_out="./result/leodos_item.rs";
	f_out_ml="./result/leodos_item.m";

	maxt=0; #number
	pktcount[maxt]=0;
	pktcount_all=0;
	avg_pktcount=0;

	s_pktcount[maxt]=0;
	s_pktcount_all=0;
	avg_s_pktcount=0;
	
} 
function round(x){
	intx=int(x);
	if(x-intx>=0.5){
		intx=intx+1;
	}
	return intx;
}
function get_t(dt, time){
	t=0;
	t=int(time/dt);
	return t;
}
function is_in_sample(dt, time){
	rtn=0;
	s_ti=int((time-t_st)/dt);
	t_dl=time-t_st-dt*s_ti;
	if (t_dl<=s_l){
		rtn=1;
	}
	return rtn;
}
function clear_given_param(){
	p_event = "";
 	p_time = "";
 	p_fromnode = "";
 	p_tonode = "";
	p_pkttype = "";
 	p_pktsize = "";
	p_flags = "";
 	p_fid = "";
 	p_srcaddr = "";
	p_dstaddr = "";
	p_seqnum = "";
	p_pktid = "";
}
function clear_array(from,to,array,val){
	for (i = from; i <= to; i++){
		array[i]=val;
	}
}
function matchp(event,time,fromnode,tonode,pkttype,pktsize,flags,fid,srcaddr,dstaddr,seqnum,pktid){
	rtn=0;
	if (time>=t_st && time<=t_sp) {
		if ((p_event==""||p_event==event)&&(p_time==""||p_time==time)&&(p_fromnode==""||p_fromnode==fromnode)&&(p_tonode==""||p_tonode==tonode)&&(p_pkttype==""||p_pkttype==pkttype)&&(p_pktsize==""||p_pktsize==pktsize)&&(p_flags==""||p_flags==flags)&&(p_fid==""||p_fid==fid)&&(p_srcaddr==""||p_srcaddr==srcaddr)&&(p_dstaddr==""||p_dstaddr==dstaddr)&&(p_seqnum==""||p_seqnum==seqnum)&&(p_pktid==""||p_pktid==pktid)) {
			rtn=1;
		}
	}
	return rtn;
}
function statistics(){
	avg_pktcount = pktcount_all/(t_sp-t_st);
	avg_s_pktcount = s_pktcount_all/(t_sp-t_st);
}
function output(tt, dv, ct, ml, count_array){	
	printf "avg_pktcount\t%f\t\n", avg_pktcount;
	printf "avg_s_pktcount\t%f\t\n", avg_s_pktcount;		

	if (tt!="") {
		printf "TitleText: %s\n", tt >> f_out;
	}
	if (dv!="") {
		printf "Device: %s\n", dv >> f_out;
	}
	
	if (ct!="") {
		printf "\"%s\n", ct >> f_out;
				
		printf "#li\t%d \t dt=%f\t s_l=%f\t t_st=%f\t t_sp=%f\t avgPktCnt=%f\n", li, dt, s_l, t_st, t_sp, avg_s_pktcount >> f_out;
		for ( i_t = int(t_st/dt); i_t < int((t_sp)/dt); i_t++ ) {
			printf "%f\t%d\n", i_t*dt, count_array[i_t] >> f_out;
			#print i_t*dt, count_array[i_t] >> f_out;
		}
		print "\n" >> f_out;

		if (ml!="") {
			printf "%%%s\t dt=%f\t s_l=%f\t t_st=%f\t t_sp=%f\t avgPktCnt=%f\n", ct, dt, s_l, t_st, t_sp, avg_s_pktcount >> f_out_ml;
			printf "t_%s(%d,:) = [ ", ct, li >> f_out_ml;
			for ( i_t = int(t_st/dt); i_t < int((t_sp)/dt); i_t++ ) {
				printf "%f ", i_t*dt >> f_out_ml;
			}
			printf "];\n" >> f_out_ml;
			printf "pktcount_%s(%d,:) = [ ", ct, li >> f_out_ml;
			for ( i_t = int(t_st/dt); i_t < int((t_sp)/dt); i_t++ ) {
				printf "%d ", count_array[i_t] >> f_out_ml;
			}
			printf "];\n" >> f_out_ml;
			print "\n" >> f_out_ml;
		}
	}	
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
   
	t=get_t(dt, time);
  	if(t > maxt){
		clear_array(maxt+1,t,pktcount,0);
		clear_array(maxt+1,t,s_pktcount,0);
		maxt=t;
 	}
	
	if (matchp(event,time,fromnode,tonode,pkttype,pktsize,flags,fid,srcaddr,dstaddr,seqnum,pktid)==1) {
		pktcount[t] = pktcount[t] + 1;
		pktcount_all = pktcount_all + 1;
		if (is_in_sample(dt, time)){
			s_pktcount[t] = s_pktcount[t] + 1;
			s_pktcount_all = s_pktcount_all + 1;			
		}
	}
}						  
END {
	statistics();
	#output(p_tt, p_dv, p_ct, p_ml, pktcount);
	output(p_tt, p_dv, p_ct, p_ml, s_pktcount);
}
