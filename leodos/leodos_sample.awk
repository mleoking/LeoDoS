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

	f_out="./result/leodos_sample.rs";
	f_out_ml="./result/leodos_sample.m";
	f_out_ci="./result/leodos_sample.ci";

	maxt=0; #number
	pktcount[maxt]=0;
	pktcount_all=0;
	avg_pkt_count=0;
		
	maxfn=0;
	maxfid=0;
	f_srcaddr[maxfn]="";
	f_dstaddr[maxfn]="";
	f_fid[maxfn]=0;
	f_pktcount[maxfn]=0;
	f_avg_pktcount[maxfn]=0;

	f_pktcounts_dfn=int((t_sp-t_st)/dt)+100;
	f_pktcounts[0]=0;
	printf "leodos_sample.awk: dt=%f s_l=%f t_st=%f t_sp=%f p_ct=%s f_pktcounts_dfn=%d\n", dt, s_l, t_st, t_sp, p_ct, f_pktcounts_dfn;
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
	for ( fn_i = 1; fn_i <= maxfn; fn_i++) {
		#if ((fs_srcaddr==f_srcaddr[fn_i] || p_srcaddr=="*") && (fs_dstaddr==f_dstaddr[fn_i] || p_dstaddr=="*") && (fs_fid==f_fid[fn_i] || p_fid=="*")) { 
		if ((index(fs_srcaddr,f_srcaddr[fn_i])==1 || p_srcaddr=="*") && (index(fs_dstaddr,f_dstaddr[fn_i])==1 || p_dstaddr=="*") && (fs_fid==f_fid[fn_i] || p_fid=="*")) { 
			if (p_srcaddr!="*"||p_dstaddr!="*"||p_fid!="*"||f_srcaddr[fn_i]=="*"){
				fn=fn_i;
			}			
			break;
		}
	}

	if (p_fid=="*")	{
		maxfid=1;
	}
	else if (fs_fid>maxfid){
		maxfid=fs_fid;
	}

	if (fn<0){
		maxfn=maxfn+1;
		fn=maxfn;
		if (p_srcaddr==""){
			f_srcaddr[fn]=fs_srcaddr;
		}else{
			f_srcaddr[fn]=p_srcaddr;
		}

		if (p_dstaddr==""){
			f_dstaddr[fn]=fs_dstaddr;
		}else{
			f_dstaddr[fn]=p_dstaddr;
		}


		if (p_fid=="*"){
			f_fid[fn]=0;
		}else{
			f_fid[fn]=fs_fid;
		}		
		f_pktcount[fn]=0;
		f_avg_pktcount[fn]=0;
		printf "fn=%d f_srcaddr=%s f_dstaddr=%s f_fid=%d\n", maxfn,f_srcaddr[fn], f_dstaddr[fn], f_fid[fn];
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
		if ((p_event==""||p_event==event)&&(p_time==""||p_time==time)&&(p_fromnode==""||p_fromnode==fromnode)&&(p_tonode==""||p_tonode==tonode)&&(p_pkttype==""||p_pkttype==pkttype)&&(p_pktsize==""||p_pktsize==pktsize)&&(p_flags==""||p_flags==flags)&&(p_fid=="*"||p_fid==""||p_fid==fid)&&(p_srcaddr=="*"||p_srcaddr==""||index(srcaddr,p_srcaddr)==1)&&(p_dstaddr=="*"||p_dstaddr==""||index(dstaddr,p_dstaddr)==1)&&(p_seqnum==""||p_seqnum==seqnum)&&(p_pktid==""||p_pktid==pktid)) {
			rtn=1;
		}
	}
	return rtn;
}
function statistics(){
	avg_pkt_count = pktcount_all/(t_sp-t_st);

	for (fn_i=1; fn_i<=maxfn; fn_i++){
		if (f_pktcount[fn_i]>0){			
			f_avg_pktcount[fn_i]=f_pktcount[fn_i]/(t_sp-t_st);
		}
	}
}
function output(tt, dv, ct, rs, ml, ci){	
	printf "avg_pkt_count\t%f\t\n", avg_pkt_count;
	printf "ur_n\t%d\t ak_n\t%d\n", ur_n, ak_n;	
	
	if (ct!="") {
		if (rs!=""){
			if (tt!="") {
				printf "TitleText: %s\n", tt >> f_out;
			}
			if (dv!="") {
				printf "Device: %s\n", dv >> f_out;
			}
			printf "#ur_n\t%d\t ak_n\t%d\t avgPktCnt=%f\n", ur_n, ak_n, avg_pkt_count >> f_out;
			for (fid_i=1; fid_i<=maxfid; fid_i++){		
				for (fn_i = 1; fn_i <= maxfn; fn_i++) {
					if (f_fid[fn_i]==fid_i||p_fid=="*"){
						printf "\"%s(%d,%d,%d)\n", ct, li, fn_i, f_fid[fn_i] >> f_out;
						printf "#%d\t%s\t%s\t%f\t%d\n", fn_i, f_srcaddr[fn_i], f_dstaddr[fn_i], f_avg_pktcount[fn_i], f_pktcount[fn_i]>> f_out;
						for (fn_ti=0; fn_ti<=maxt; fn_ti++){
							prefix=f_pktcounts_dfn*(fn_i-1);
							printf "%f\t%f\n", t_st+fn_ti*dt, f_pktcounts[prefix+fn_ti] >> f_out;
						}
						print "\n" >> f_out;			
					}
				}
			}
			print "\n" >> f_out;
		}		

		if (ml!="") {
			printf "%%%s\t ur_n\t%d\t ak_n\t%d\t avgPktCnt=%f\n", ct, ur_n, ak_n, avg_pkt_count >> f_out_ml;
			for (fid_i=1; fid_i<=maxfid; fid_i++){
				for (fn_i = 1; fn_i <= maxfn; fn_i++) {
					if (f_fid[fn_i]==fid_i||p_fid=="*"){
						printf "%%%d %d\t%s\t%s\t%f\t%d\n", fid_i, fn_i, f_srcaddr[fn_i], f_dstaddr[fn_i], f_avg_pktcount[fn_i], f_pktcount[fn_i] >> f_out_ml;			
						printf "%s_time{%d, %d}.fid = %d;\n", ct, li, fn_i, f_fid[fn_i]>> f_out_ml;						
						printf "%s_time{%d, %d}.data = [\t", ct, li, fn_i >> f_out_ml;
						for (fn_ti=0; fn_ti<=maxt; fn_ti++){
							prefix=f_pktcounts_dfn*(fn_i-1);
							printf "%f\t", t_st+fn_ti*dt >> f_out_ml;
						}				
						printf "];\n" >> f_out_ml;
						printf "%s_pktcnt{%d, %d}.fid = %d;\n", ct, li, fn_i, f_fid[fn_i] >> f_out_ml;
						printf "%s_pktcnt{%d, %d}.data = [\t", ct, li, fn_i >> f_out_ml;
						for (fn_ti=0; fn_ti<=maxt; fn_ti++){
							prefix=f_pktcounts_dfn*(fn_i-1);
							printf "%d\t", f_pktcounts[prefix+fn_ti] >> f_out_ml;
						}				
						printf "];\n" >> f_out_ml;
					}					
				}
			}			
			printf "\n" >> f_out_ml;
		}
		if (ci!="") {
			printf "li\t%d\tdt\t%f\ts_l\t%f\tt_st\t%f\tt_sp\t%f\tavg_pktcnt\t%f\n", li, dt, s_l, t_st, t_sp, avg_pktcnt >> f_out_ci;
			for (fn_i = 1; fn_i <= maxfn; fn_i++) {
				printf "fid\t%d\n", f_fid[fn_i] >> f_out_ci;
				printf "time\t" >> f_out_ci;
				for (fn_ti=0; fn_ti<=maxt; fn_ti++){
					prefix=f_pktcounts_dfn*(fn_i-1);
					printf "%f\t", t_st+fn_ti*dt >> f_out_ci;
				}				
				printf "\n" >> f_out_ci;
				printf "pktcnt\t" >> f_out_ci;
				for (fn_ti=0; fn_ti<=maxt; fn_ti++){
					prefix=f_pktcounts_dfn*(fn_i-1);
					printf "%d\t", f_pktcounts[prefix+fn_ti] >> f_out_ci;
				}				
				printf "\n--\n" >> f_out_ci;
			}
		}
	}	
}
function mod(number, base){
	dn=int(number/base);
	modv=number-dn*base;
	return modv;
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
	
	if (mod(pktid, 100000)==0){
		printf "pktid:%d\n", pktid;
	}	
   

	if (time>=t_st && time<t_sp) {
		t=get_t(dt, time);
	  	if(t > maxt){
			clear_array(maxt+1,t,pktcount,0);
			for (fn_i=1; fn_i<=maxfn; fn_i++){
				prefix=f_pktcounts_dfn*(fn_i-1);
				clear_array(prefix+maxt+1,prefix+t,f_pktcounts,0);			
			}
			maxt=t;
		}
	
		if (matchp(event,time,fromnode,tonode,pkttype,pktsize,flags,fid,srcaddr,dstaddr,seqnum,pktid)==1) {
			if (is_in_sample(dt, time)){
				pktcount[t] = pktcount[t] + 1;
				pktcount_all = pktcount_all + 1;

				fn=get_fn(srcaddr,dstaddr,fid);
				prefix=f_pktcounts_dfn*(fn-1);
				f_pktcounts[prefix+t]=f_pktcounts[prefix+t]+1;
				f_pktcount[fn]=f_pktcount[fn]+1;		
			}
		
		}
 	}	
	
}						  
END {
	statistics();
	output(p_tt, p_dv, p_ct, p_rs, p_ml, p_ci);
}
