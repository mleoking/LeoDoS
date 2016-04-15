# Copyright (c) 2010-2012 Changwang Zhang (mleoking@gmail.com). All rights reserved.
#
# This Active Queue Management and Denial-of-Service (AQM&DoS) Simulation Platform was established
# for the Robust Random Early Detection (RRED) algorithm [1]. If you use any part of this platform
# in your research, you have the responsibility to cite this platform as:
#
# The experiments (or simulations) are conducted on the AQM&DoS Simulation Platform that was created 
# for the Robust Random Early Detection (RRED) algorithm [1].
#
# References:
# 1. Changwang Zhang, Jianping Yin, Zhiping Cai, and Weifeng Chen, RRED: Robust RED Algorithm to Counter Low-rate Denial-of-Service Attacks, IEEE Communications Letters, vol. 14, pp. 489-491, 2010.
#
# Platform Homepage: http://sites.google.com/site/cwzhangres/home/posts/aqmdossimulationplatform
#
# Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
# 1. Cite this platform in the redistribution using the way mentioned above.
# 2. The above statements are kept in the redistribution.

BEGIN {
	if (dt=="") {
		dt=0.01; #second
	}
	if (t_st=="") {
		t_st=0;#calculate from 0 second
	}
	if (t_sp=="") {
		t_sp=240;#calculate to 240 second
	}
	if (p_ct=="") {
		p_ct="pktcount";
	}

	f_out="./result/leodos_queue.rs";

	maxt=0; #number
	pktcount[maxt]=0;
	eq_pktcount[maxt]=0;
	dq_pktcount[maxt]=0;
	dp_pktcount[maxt]=0;
	r_pktcount[maxt]=0;
	pktcount_now=0;
	avg_pkt_count=0;

	eq_pktcount_f1[maxt]=0;
	dq_pktcount_f1[maxt]=0;
	dp_pktcount_f1[maxt]=0;
	r_pktcount_f1[maxt]=0;
	
	eq_pktcount_f2[maxt]=0;
	dq_pktcount_f2[maxt]=0;	
	dp_pktcount_f2[maxt]=0;
	r_pktcount_f2[maxt]=0;
	
	printf "leodos_queue_awk: dt=%f s_l=%f t_st=%f t_sp=%f ur_n=%d ak_n=%d ur_st=%f ur_sp=%f ak_st=%f ak_sp=%f p_ct=%s \n", dt, s_l, t_st, t_sp, ur_n, ak_n, ur_st, ur_sp, ak_st, ak_sp, p_ct;
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
	t=int((time-t_st)/dt);
	return t;
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
function cal_nthroughput(){
	pc_f1_normal=0;
	pc_f1_attack=0;
	pc_f2_normal=0;
	pc_f2_attack=0;

	r_pc_f1_normal=0;
	r_pc_f1_attack=0;
	r_pc_f2_normal=0;
	r_pc_f2_attack=0;

#	nthroughput=0.0;
	for ( i_t = 1; i_t <= maxt; i_t++ ) {
		time_t=t_st+i_t*dt;		
		if (time_t>=ak_st && time_t<=ak_sp){
			pc_f1_attack=pc_f1_attack+eq_pktcount_f1[i_t];
			pc_f2_attack=pc_f2_attack+eq_pktcount_f2[i_t];
			r_pc_f1_attack=r_pc_f1_attack+r_pktcount_f1[i_t];
			r_pc_f2_attack=r_pc_f2_attack+r_pktcount_f2[i_t];
		#}else if (time_t>=ur_st && time_t<=ur_sp){
		}else if (time_t>=ur_st && time_t<=ak_st){
			pc_f1_normal=pc_f1_normal+eq_pktcount_f1[i_t];
			pc_f2_normal=pc_f2_normal+eq_pktcount_f2[i_t];
			r_pc_f1_normal=r_pc_f1_normal+r_pktcount_f1[i_t];
			r_pc_f2_normal=r_pc_f2_normal+r_pktcount_f2[i_t];
		}		
	}

	attack_time_length=ak_sp-ak_st;
	#normal_time_length=ur_sp-ur_st-attack_time_length;
	normal_time_length=ak_st-ur_st;

	rate_f1_attack=pc_f1_attack/attack_time_length;
	rate_f1_normal=pc_f1_normal/normal_time_length;

	r_rate_f1_attack=r_pc_f1_attack/attack_time_length;
	r_rate_f1_normal=r_pc_f1_normal/normal_time_length;

	rate_f2_attack=pc_f2_attack/attack_time_length;
	rate_f2_normal=pc_f2_normal/normal_time_length;

	r_rate_f2_attack=r_pc_f2_attack/attack_time_length;
	r_rate_f2_normal=r_pc_f2_normal/normal_time_length;
	

	nth_f1=-1;
	nth_f2=-1;
	if (rate_f1_normal>0) {
		nth_f1=rate_f1_attack/rate_f1_normal;
	}
	if (rate_f2_normal>0) {
		nth_f2=rate_f2_attack/rate_f2_normal;
	}

	r_nth_f1=-1;
	r_nth_f2=-1;
	if (r_rate_f1_normal>0) {
		r_nth_f1=r_rate_f1_attack/r_rate_f1_normal;
	}
	if (r_rate_f2_normal>0) {
		r_nth_f2=r_rate_f2_attack/r_rate_f2_normal;
	}	
	


	#printf "rate_f1_normal\t%f\trate_f1_attack\t%f\tnth_f1\t%f\trate_f2_normal\t%f\trate_f2_attack\t%f\tnth_f2\t%f\n", rate_f1_normal, rate_f1_attack, nth_f1, rate_f2_normal, rate_f2_attack, nth_f2;	
	#printf "r_rate_f1_normal\t%f\tr_rate_f1_attack\t%f\tr_nth_f1\t%f\tr_rate_f2_normal\t%f\tr_rate_f2_attack\t%f\tr_nth_f2\t%f\n", r_rate_f1_normal, r_rate_f1_attack, r_nth_f1, r_rate_f2_normal, r_rate_f2_attack, r_nth_f2;	
	printf "rate_f1_normal\t%f\trate_f1_attack\t%f\tnth_f1\t%f\trate_f2_attack\t%f\n", r_rate_f1_normal, r_rate_f1_attack, r_nth_f1, r_rate_f2_attack;	
}
function statistics(){
	pktcount_all = 0;
	pktcount_nt = 0;
	for ( i_t = int(t_st/dt); i_t <= int((t_sp)/dt); i_t++ ) {
		pktcount_all = pktcount_all + pktcount[i_t];
		pktcount_nt = pktcount_nt + 1;
	}
	avg_pkt_count = pktcount_all/pktcount_nt;
	#printf "avg_pkt_count\t%f\t\n", avg_pkt_count;	
	if (ur_st!="" && ur_sp!="" && ak_st!="" && ak_sp!=""){
		cal_nthroughput();
	}	
}
function output(tt, dv, ct, rs, ml, ci, count_array){	
	if (tt!="") {
		printf "TitleText: %s\n", tt >> f_out;
	}
	if (dv!="") {
		printf "Device: %s\n", dv >> f_out;
	}
	
	if (ct!="") {
		if (rs!=""){
			printf "\"%s\n", ct >> f_out;
			for ( i_t = 0; i_t <= maxt; i_t++ ) {
				printf "%f\t%d\n", t_st+i_t*dt, count_array[i_t] >> f_out;
			}
			print "\n" >> f_out;
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
   
	if (time>=t_st && time<t_sp) {
		t=get_t(dt, time);
	  	if(t > maxt){
			clear_array(maxt+1,t,pktcount,pktcount_now);
			clear_array(maxt+1,t,eq_pktcount,0);
			clear_array(maxt+1,t,dq_pktcount,0);
			clear_array(maxt+1,t,dp_pktcount,0);
			clear_array(maxt+1,t,r_pktcount,0);
	
			clear_array(maxt+1,t,eq_pktcount_f1,0);
			clear_array(maxt+1,t,dq_pktcount_f1,0);
			clear_array(maxt+1,t,dp_pktcount_f1,0);
			clear_array(maxt+1,t,r_pktcount_f1,0);
	
			clear_array(maxt+1,t,eq_pktcount_f2,0);
			clear_array(maxt+1,t,dq_pktcount_f2,0);
			clear_array(maxt+1,t,dp_pktcount_f2,0);
			clear_array(maxt+1,t,r_pktcount_f2,0);
	
			maxt=t;
 		}
		
		if (event == "+" ) {
			eq_pktcount[t] = eq_pktcount[t] + 1;
			pktcount[t] = pktcount[t] + 1;
			pktcount_now = pktcount_now + 1;
			if (fid==1){
				eq_pktcount_f1[t] = eq_pktcount_f1[t] + 1;			
			}
			if (fid==2){
				eq_pktcount_f2[t] = eq_pktcount_f2[t] + 1;			
			}		
		}
		if (event == "-" ) {
			dq_pktcount[t] = dq_pktcount[t] + 1;
			pktcount[t] = pktcount[t] - 1;
			pktcount_now = pktcount_now - 1;
			if (fid==1){
				dq_pktcount_f1[t] = dq_pktcount_f1[t] + 1;			
			}
			if (fid==2){
				dq_pktcount_f2[t] = dq_pktcount_f2[t] + 1;			
			}
		}
		if (event == "d" ) {
			dp_pktcount[t] = dp_pktcount[t] + 1;
			pktcount[t] = pktcount[t] - 1;
			pktcount_now = pktcount_now - 1;
			if (fid==1){
				dp_pktcount_f1[t] = dp_pktcount_f1[t] + 1;			
			}
			if (fid==2){
				dp_pktcount_f2[t] = dp_pktcount_f2[t] + 1;			
			}
		}
		if (event == "r" ) {
			r_pktcount[t] = r_pktcount[t] + 1;			
			if (fid==1){
				r_pktcount_f1[t] = r_pktcount_f1[t] + 1;			
			}
			if (fid==2){
				r_pktcount_f2[t] = r_pktcount_f2[t] + 1;			
			}
		}

	}	
}						  
END {
	statistics();
	output(p_tt, p_dv, "pkcount", p_rs, p_ml, p_ci, pktcount);
	#output(p_tt, p_dv, "eq_pkcount", p_rs, p_ml, p_ci, eq_pktcount);
	#output(p_tt, p_dv, "dq_pkcount", p_rs, p_ml, p_ci, dq_pktcount);
	#output(p_tt, p_dv, "dp_pkcount", p_rs, p_ml, p_ci, dp_pktcount);
	output(p_tt, p_dv, "r_pkcount", p_rs, p_ml, p_ci, r_pktcount);

	output(p_tt, p_dv, "eq_pkcount_f1", p_rs, p_ml, p_ci, eq_pktcount_f1);
	#output(p_tt, p_dv, "dq_pkcount_f1", p_rs, p_ml, p_ci, dq_pktcount_f1);
	#output(p_tt, p_dv, "dp_pkcount_f1", p_rs, p_ml, p_ci, dp_pktcount_f1);
	output(p_tt, p_dv, "r_pkcount_f1", p_rs, p_ml, p_ci, r_pktcount_f1);

	#output(p_tt, p_dv, "eq_pkcount_f2", p_rs, p_ml, p_ci, eq_pktcount_f2);
	#output(p_tt, p_dv, "dq_pkcount_f2", p_rs, p_ml, p_ci, dq_pktcount_f2);
	#output(p_tt, p_dv, "dp_pkcount_f2", p_rs, p_ml, p_ci, dp_pktcount_f2);
	output(p_tt, p_dv, "r_pkcount_f2", p_rs, p_ml, p_ci, r_pktcount_f2);
}
