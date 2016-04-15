BEGIN {
	if (dt=="") {
		dt=0.01; #second
	}
	if (s_l=="") {
		s_l=0.01; #sample length is 1s.
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
	if (bn_qs==""){		
		bn_qs=50;
	}
	

	f_out="./result/leodos_cpr.rs";
	f_out_ml="./result/leodos_cpr.m";

	maxt=0; #number
	pktcount[maxt]=0;
	pktcount_avg_past_s[maxt]=0;
	pktcount_max_past_s[maxt]=0;
	qsize_avg_past_s[maxt]=0;

	pktcount_pastlength=1;
	pktcount_avg_past=0;
	pktcount_avg_df=2;
	pktcount_max_past=0;
	pktcount_max_df=0.80;

	qsize[maxt]=0;#!!!! Use qsize to do cpr must t_st=0 other wise the qsize is not correct.
	qsize_now=0;
	qsize_avg_df=0.5;
	qsize_pastlength=1;
	qsize_avg_past=0;

	pktcount_all=0;
	avg_pkt_count=0;

	d_pktcount[maxt]=0;
	d_pktcount_all=0;
	d_avg_pkt_count=0;

	e_pktcount[maxt]=0;
	e_pktcount_all=0;
	e_avg_pkt_count=0;

	ro_dpna=-1;#ratio of dropped packets to all packets when there is no attack
	ro_dp=-1;

	rthroughput[maxt]=0;
	rthroughput_all=0;
	rthroughput_avg=0;

	ethroughput[maxt]=0;
	ethroughput_all=0;
	ethroughput_avg=0;

	dthroughput[maxt]=0;
	dthroughput_all=0;
	dthroughput_avg=0;

	rthroughput_pastlength=1;#this pastlength is different from previous ones
	rthroughput_max_past=0;
	rthroughput_max_df=0.9;

	rthroughput_avg_past=0;
	rthroughput_avg_df=2;

	qsize_past_tn=int(qsize_pastlength/dt);
	pktcount_past_tn=int(pktcount_pastlength/dt);
	rthroughput_past_tn=int(rthroughput_pastlength/dt);


	maxfn=0;
	maxfid=0;
	f_srcaddr[maxfn]="";
	f_dstaddr[maxfn]="";
	f_fid[maxfn]=0;
	f_pktcount[maxfn]=0;
	f_pktcount_tmp[maxfn]=0;
	f_pktcount_tmp2[maxfn]=0;
	f_cong_pktcount[maxfn]=0;
	f_avg_pktcount[manfn]=0;
	f_cpr[maxfn]=0;

	max_fid_cpr[maxfid]=0;
	min_fid_cpr[maxfid]=1;
	fid_pktcount[maxfid]=0;
	fid_cong_pktcount[maxfid]=0;
	fid_cpr[maxfid]=0;

	ur_n_dtk=0;#number of detected users
	ak_n_dtk=0;#number of detected attackers

	false_positive_rate=0;
	detection_rate=0;
	printf "leodos_cpr.awk: R%s->R%s dt=%f s_l=%f t_st=%f t_sp=%f bn_qs=%d p_ct=%s qsize_past_tn=%d pktcount_past_tn=%d\n", p_fromnode, p_tonode, dt, s_l, t_st, t_sp, bn_qs, p_ct, qsize_past_tn, pktcount_past_tn;
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
function is_in_sample(dt, time){
	rtn=0;
	s_ti=int((time-t_st)/dt);
	t_dl=time-t_st-dt*s_ti;
	if (t_dl<=s_l){
		rtn=1;
	}
	return rtn;
}
function get_fn(fs_srcaddr,fs_dstaddr,fs_fid){
	fn=-1;
	for (fn_i = 1; fn_i <= maxfn; fn_i++) {
		if (fs_srcaddr==f_srcaddr[fn_i] && fs_dstaddr==f_dstaddr[fn_i] && fs_fid==f_fid[fn_i]) { 
			fn=fn_i;
			break;
		}
	}
	#here is based on the assumption that fs_fid would appears in succession
	if (fs_fid>maxfid){
		maxfid=fs_fid;
		max_fid_cpr[maxfid]=0;
		min_fid_cpr[maxfid]=1;
		fid_pktcount[maxfid]=0;
		fid_cong_pktcount[maxfid]=0;
		fid_cpr[maxfid]=0;
	}
	if (fn<0){
		maxfn=maxfn+1;
		fn=maxfn;
		f_srcaddr[fn]=fs_srcaddr;
		f_dstaddr[fn]=fs_dstaddr;
		f_fid[fn]=fs_fid;
		f_pktcount[fn]=0;
		f_pktcount_tmp[fn]=0;
		f_cong_pktcount[fn]=0;
		f_avg_pktcount[fn]=0;
		f_cpr[fn]=0;
		if (fs_fid==1){
			ur_n_dtk=ur_n_dtk+1;
		}
		if (fs_fid==2){
			ak_n_dtk=ak_n_dtk+1;
		}
	}
	return fn;
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
	if (time>=t_st && time<t_sp) {
		if ((p_event==""||p_event==event)&&(p_time==""||p_time==time)&&(p_fromnode==""||p_fromnode==fromnode)&&(p_tonode==""||p_tonode==tonode)&&(p_pkttype==""||p_pkttype==pkttype)&&(p_pktsize==""||p_pktsize==pktsize)&&(p_flags==""||p_flags==flags)&&(p_fid==""||p_fid==fid)&&(p_srcaddr==""||p_srcaddr==srcaddr)&&(p_dstaddr==""||p_dstaddr==dstaddr)&&(p_seqnum==""||p_seqnum==seqnum)&&(p_pktid==""||p_pktid==pktid)) {
			rtn=1;
		}
	}
	return rtn;
}
function statistics(){
	avg_pkt_count = pktcount_all/(t_sp-t_st);
	d_avg_pkt_count = d_pktcount_all/(t_sp-t_st);
	e_avg_pkt_count = e_pktcount_all/(t_sp-t_st);
	rthroughput_avg=rthroughput_all/(t_sp-t_st);
	ethroughput_avg=ethroughput_all/(t_sp-t_st);
	dthroughput_avg=dthroughput_all/(t_sp-t_st);
	ro_dp=d_pktcount_all/e_pktcount_all;

	
	false_positive_count=0;
	detection_count=0;

	for (fid_i=1; fid_i<=maxfid; fid_i++){
		fid_cpr[fid_i]=fid_cong_pktcount[fid_i]/fid_pktcount[fid_i];
	}


	for (fn_i=1; fn_i<=maxfn; fn_i++){
		if (f_pktcount[fn_i]>0){			
			f_avg_pktcount[fn_i]=f_pktcount[fn_i]/(t_sp-t_st);
			f_cpr[fn_i]=f_cong_pktcount[fn_i]/f_pktcount[fn_i];

			thefid=f_fid[fn_i];
			if (f_cpr[fn_i]>=d_cpr){
				if (thefid==1) {
					false_positive_count++;
				}
				if (thefid==2) {
					detection_count++;
				}
			}			
			
			if (f_cpr[fn_i]>max_fid_cpr[thefid]){
				max_fid_cpr[thefid]=f_cpr[fn_i];
			}
			if (f_cpr[fn_i]<min_fid_cpr[thefid]){
				min_fid_cpr[thefid]=f_cpr[fn_i];
			}

		}
	}

	false_positive_rate=false_positive_count/ur_n_dtk;
	detection_rate=detection_count/ak_n_dtk;

	printf "rthroughput_max_past\t %d\t rthroughput_pastlength\t %d\n",rthroughput_max_past, rthroughput_pastlength;
	printf "rthroughput_avg\t %f\t ethroughput_avg\t %f\t dthroughput_avg\t %f\n",rthroughput_avg, ethroughput_avg, dthroughput_avg;
	printf "avg_pkt_count\t%f\t d_avg_pkt_count\t%f\t e_avg_pkt_count\t%f\t\n", avg_pkt_count, d_avg_pkt_count, e_avg_pkt_count;
	printf "ur_n_dtk\t%d\t ak_n_dtk\t%d\n", ur_n_dtk, ak_n_dtk;
	for (fid_i=1; fid_i<=maxfid; fid_i++){
		printf "fid=%d max_fid_cpr=%f min_fid_cpr=%f fid_cpr=%d/%d=%f\n", fid_i, max_fid_cpr[fid_i], min_fid_cpr[fid_i], fid_cong_pktcount[fid_i], fid_pktcount[fid_i], fid_cpr[fid_i];
	}		
	printf "d_cpr=%f false_positive_rate\t%f\t detection_rate\t%f\n", d_cpr, false_positive_rate, detection_rate;
	printf "ro_dpna=%f\t ro_dp=%f\n", ro_dpna, ro_dp;
}
function output(tt, dv, ct, rs, ml, ci){
	if (ct!="") {
		if (rs!=""){
			print "\n" >> f_out;	
			if (tt!="") {
				printf "TitleText: %s\n", tt >> f_out;
			}
			if (dv!="") {
				printf "Device: %s\n", dv >> f_out;
			}
			printf "\"%s\n", ct >> f_out;
			printf "#R%s->R%s dt=%f s_l=%f t_st=%f t_sp=%f bn_qs=%d p_ct=%s qsize_past_tn=%d pktcount_past_tn=%d\n", p_fromnode, p_tonode, dt, s_l, t_st, t_sp, bn_qs, p_ct, qsize_past_tn, pktcount_past_tn >> f_out;
			printf "#ur_n_dtk\t%d\t ak_n_dtk\t%d\t avgPktCnt=%f\t dAvgPktCnt=%f\t d_cpr=%f\t false_positive_rate=%f\t detection_rate=%f\n", ur_n_dtk, ak_n_dtk, avg_pkt_count, d_avg_pkt_count, d_cpr, false_positive_rate, detection_rate >> f_out;
			printf "#li\t%d\tlj\t%d\n", li, lj >> f_out;
			printf "#ro_dpna\t%f\t ro_dp\t%f\n", ro_dpna, ro_dp >> f_out;
			for (fid_i=1; fid_i<=maxfid; fid_i++){
				printf "#fid=%d max_fid_cpr=%f min_fid_cpr=%f fid_cpr=%d/%d=%f\n", fid_i, max_fid_cpr[fid_i], min_fid_cpr[fid_i], fid_cong_pktcount[fid_i], fid_pktcount[fid_i], fid_cpr[fid_i] >> f_out;
				for (fn_i = 1; fn_i <= maxfn; fn_i++) {
					if (f_fid[fn_i]==fid_i){
						printf "#fid:%d\tfn_i:%d\t%s->%s\tavg_pktcnt:%f\tcpr:%d/%d=%f\n", fid_i, fn_i, f_srcaddr[fn_i], f_dstaddr[fn_i], f_avg_pktcount[fn_i], f_cong_pktcount[fn_i], f_pktcount[fn_i], f_cpr[fn_i]>> f_out;
						printf "%d\t%f\n", fn_i, f_cpr[fn_i]>> f_out;
					}			
				}
			}		
			print "\n" >> f_out;
		}		

		if (ml!="") {
			printf "%%%s\t ur_n_dtk\t%d\t ak_n_dtk\t%d\t avgPktCnt=%f\t dAvgPktCnt=%f\n", ct, ur_n_dtk, ak_n_dtk, avg_pkt_count, d_avg_pkt_count >> f_out_ml;
			printf "%%R%s->R%s dt=%f s_l=%f t_st=%f t_sp=%f bn_qs=%d p_ct=%s qsize_past_tn=%d pktcount_past_tn=%d\n", p_fromnode, p_tonode, dt, s_l, t_st, t_sp, bn_qs, p_ct, qsize_past_tn, pktcount_past_tn >> f_out_ml;
			printf "%%" >> f_out_ml;
			for (fn_i = 1; fn_i <= maxfn; fn_i++) {
				printf "fid:%d fn_i:%d %s->%s avg_pktcnt:%f cpr:%d/%d=%f\t", f_fid[fn_i], fn_i, f_srcaddr[fn_i], f_dstaddr[fn_i], f_avg_pktcount[fn_i], f_cong_pktcount[fn_i], f_pktcount[fn_i], f_cpr[fn_i]>> f_out_ml;
			}
			printf "\n" >> f_out_ml;
			pre_index=li;
			if (lj!="") {
				pre_index=li","lj;
			}
			printf "d_cpr(%s)=%f;\nfpr(%s)=%f;dtr(%s)=%f;\n", pre_index, d_cpr, pre_index, false_positive_rate, pre_index, detection_rate >> f_out_ml;
			printf "ro_dpna(%s)=%f;ro_dp(%s)=%f;\n", pre_index, ro_dpna, pre_index, ro_dp >> f_out_ml;
			for (fid_i=1; fid_i<=maxfid; fid_i++){
				printf "%s_max_cpr{%s,%d}=%f; %s_min_cpr{%s,%d}=%f; %s_avg_cpr{%s,%d}=%f;%%%d/%d\n", ct, pre_index, fid_i, max_fid_cpr[fid_i], ct, pre_index, fid_i, min_fid_cpr[fid_i], ct, pre_index, fid_i, fid_cpr[fid_i], fid_cong_pktcount[fid_i], fid_pktcount[fid_i] >> f_out_ml;		
				printf "%s_i_f{%s,%d} = [ ", ct, pre_index, fid_i >> f_out_ml;
				for (fn_i = 1; fn_i <= maxfn; fn_i++) {
					if (f_fid[fn_i]==fid_i){
						printf "%d ", fn_i >> f_out_ml;
					}
				}
				printf "];\n" >> f_out_ml;
				printf "%s_cpr_f{%s,%d} = [ ", ct, pre_index, fid_i >> f_out_ml;
				for (fn_i = 1; fn_i <= maxfn; fn_i++) {
					if (f_fid[fn_i]==fid_i){
						printf "%f ", f_cpr[fn_i] >> f_out_ml;
					}
				}
				printf "];\n" >> f_out_ml;
			}
			printf "\n" >> f_out_ml;
		}
	}	
}
function output_array(tt, dv, ct, rs, ml, ci, array){
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
				printf "%f\t%.3f\n", t_st+i_t*dt, array[i_t] >> f_out;
			}
			print "\n" >> f_out;
		}		

		if (ml!="") {			
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

	#Add p_fromnode p_tonode for leodos.mbn.tcl
	if (time>=t_st && time<t_sp && (p_fromnode==""||p_fromnode==fromnode) && (p_tonode==""||p_tonode==tonode)) {
		t=get_t(dt, time);
	  	if(t > maxt){
			clear_array(maxt+1,t,pktcount,0);
			clear_array(maxt+1,t,d_pktcount,0);
			clear_array(maxt+1,t,e_pktcount,0);
			clear_array(maxt+1,t,rthroughput,0);
			clear_array(maxt+1,t,ethroughput,0);
			clear_array(maxt+1,t,dthroughput,0);
			
			if (maxt>=qsize_past_tn){
				qsize_sum=0;
				for(qsize_i=maxt-qsize_past_tn;qsize_i<maxt;qsize_i++){
					qsize_sum=qsize_sum+qsize[qsize_i];
				}
				qsize_avg_past=qsize_sum/qsize_past_tn;
			}else{
				qsize_avg_past=qsize_now;
			}
					
			if (maxt>=pktcount_past_tn){
				pktcount_sum=0;
				pktcount_max_past=0;
				for(pktcount_i=maxt-pktcount_past_tn;pktcount_i<maxt;pktcount_i++){
					pktcount_sum=pktcount_sum+pktcount[pktcount_i];
					if (pktcount[pktcount_i]>pktcount_max_past){
						pktcount_max_past=pktcount[pktcount_i];
					}
				}
				pktcount_avg_past=pktcount_sum/pktcount_past_tn;
			}else{
				pktcount_avg_past=pktcount[maxt];
				pktcount_max_past=pktcount[maxt]*pktcount_avg_df;
			}

			if (maxt>=rthroughput_past_tn){
				rthroughput_sum=0;
				for(rthroughput_i=maxt-rthroughput_past_tn;rthroughput_i<maxt;rthroughput_i++){
					rthroughput_sum=rthroughput_sum+rthroughput[rthroughput_i];
				}
				rthroughput_avg_past=rthroughput_sum/rthroughput_past_tn;
				if (rthroughput_sum > rthroughput_max_past){
					rthroughput_max_past=rthroughput_sum;
				}			
			}else{
				rthroughput_avg_past=rthroughput[maxt];
				rthroughput_max_past=rthroughput[maxt]*rthroughput_past_tn;
			}

			for (fn_i=1; fn_i<=maxfn; fn_i++){
				if (f_pktcount_tmp[fn_i]>0){
					f_qs=(qsize[maxt]-qsize_avg_past>=bn_qs*qsize_avg_df);
					f_dp=(d_pktcount[maxt]>0);
					f_avp=(pktcount[maxt]>=pktcount_avg_df*pktcount_avg_past);
					f_mxp=(pktcount[maxt]>=pktcount_max_df*pktcount_max_past);
					f_mxr=(ethroughput[maxt]>=rthroughput_max_df*rthroughput_max_past*dt);
					
					#f_mxp||f_dp
					#f_dp||(f_avp&&f_mxr)
					thefid=f_fid[fn_i];
					if (f_dp){
						f_cong_pktcount[fn_i]=f_cong_pktcount[fn_i]+f_pktcount_tmp[fn_i];

						fid_cong_pktcount[thefid]=fid_cong_pktcount[thefid]+f_pktcount_tmp[fn_i];
						#if(d_pktcount[maxt-1]==0){
						#	f_cong_pktcount[fn_i]=f_cong_pktcount[fn_i]+f_pktcount_tmp[fn_i]+f_pktcount_tmp2[fn_i];
						#}							
						f_pktcount[fn_i]=f_pktcount[fn_i]+f_pktcount_tmp[fn_i];
						fid_pktcount[thefid]=fid_pktcount[thefid]+f_pktcount_tmp[fn_i];
					}else{
						f_pktcount[fn_i]=f_pktcount[fn_i]+f_pktcount_tmp[fn_i];
						fid_pktcount[thefid]=fid_pktcount[thefid]+f_pktcount_tmp[fn_i];
					}					
					f_pktcount_tmp2[fn_i]=f_pktcount_tmp[fn_i];
					f_pktcount_tmp[fn_i]=0;
				}			
			}
			clear_array(maxt,t,qsize,qsize_now);
			clear_array(maxt,t,pktcount_avg_past_s,pktcount_avg_past);
			clear_array(maxt,t,pktcount_max_past_s,pktcount_max_past);
			clear_array(maxt,t,qsize_avg_past_s,qsize_avg_past);
			maxt=t;
			
	 	}

		if ((p_fromnode==""||p_fromnode==fromnode) && (p_tonode==""||p_tonode==tonode)){
			if (event=="+") {
				qsize_now++;
				#ethroughput[t] = ethroughput[t] + pktsize;
				#ethroughput_all = ethroughput_all + pktsize;
				#e_pktcount[t] = e_pktcount[t] + 1;
				#e_pktcount_all = e_pktcount_all + 1;
			}

			if (event=="-") {
				if (qsize_now>0){
					qsize_now--;
				}				
			}			
			
			if (event=="d") {
				if (qsize_now>0){
					qsize_now--;
				}
				d_pktcount[t] = d_pktcount[t] + 1;
				d_pktcount_all = d_pktcount_all + 1;
				#dthroughput[t] = dthroughput[t] + pktsize;
				#dthroughput_all = dthroughput_all + pktsize;				
			}

			if (event=="r") {
				rthroughput[t] = rthroughput[t] + pktsize;
				rthroughput_all = rthroughput_all + pktsize;
			}

		}
		
		if (ro_dpna<0 && ak_st-time<1 && ak_st-time>0 ) {
			ro_dpna=d_pktcount_all/e_pktcount_all;
		}
		
		if (matchp(event,time,fromnode,tonode,pkttype,pktsize,flags,fid,srcaddr,dstaddr,seqnum,pktid)==1) {
			pktcount[t] = pktcount[t] + 1;
			pktcount_all = pktcount_all + 1;
			if (event=="+") {
				ethroughput[t] = ethroughput[t] + pktsize;
				ethroughput_all = ethroughput_all + pktsize;
				e_pktcount[t] = e_pktcount[t] + 1;
				e_pktcount_all = e_pktcount_all + 1;
				if (is_in_sample(dt, time) && m_fg==""){
					fn=get_fn(srcaddr,dstaddr,fid);
					f_pktcount_tmp[fn]=f_pktcount_tmp[fn]+1;			
				}
			}
			if (event=="d") {
				dthroughput[t] = dthroughput[t] + pktsize;
				dthroughput_all = dthroughput_all + pktsize;				
			}			
			
		}
	}   
	
}						  
END {
	statistics();
	if (m_fg=="") { output(p_tt, p_dv, p_ct, p_rs, p_ml, p_ci);}
	if (m_fg!="") {
		#output_array(p_tt, p_dv, "pktcount", p_rs, p_ml, p_ci, pktcount);	
		#output_array(p_tt, p_dv, "d_pktcount", p_rs, p_ml, p_ci, d_pktcount);
		#output_array(p_tt, p_dv, "e_pktcount", p_rs, p_ml, p_ci, e_pktcount);
		#output_array(p_tt, p_dv, "pktcount_avg_past_s", p_rs, p_ml, p_ci, pktcount_avg_past_s);
		#output_array(p_tt, p_dv, "pktcount_max_past_s", p_rs, p_ml, p_ci, pktcount_max_past_s);
		#output_array(p_tt, p_dv, "qsize", p_rs, p_ml, p_ci, qsize);
		#output_array(p_tt, p_dv, "qsize_avg_past_s", p_rs, p_ml, p_ci, qsize_avg_past_s);
		#output_array(p_tt, p_dv, "rthroughput", p_rs, p_ml, p_ci, rthroughput);
		output_array(p_tt, p_dv, "ethroughput", p_rs, p_ml, p_ci, ethroughput);
		output_array(p_tt, p_dv, "dthroughput", p_rs, p_ml, p_ci, dthroughput);
	}
}
