BEGIN {
	if (t_st=="") {
		t_st=25;#calculate from 25 second
	}
	if (t_sp=="") {
		t_sp=215;#calculate to 215 second
	}
	if (p_ct=="") {
		p_ct="value";
	}
	if (dt=="") {
		dt=0.01; #second
	}

	maxt=0; #number
	output_file="./result/leodos_tcp.rs";
	cwnd_[maxt]=0;
	cwnd_n[maxt]=0;
	rtt_[maxt]=0;
	rtt_n[maxt]=0;
	srtt_[maxt]=0;
	srtt_n[maxt]=0;
	rttvar_[maxt]=0;
	rttvar_n[maxt]=0;
} 
function get_t(dt, time){
	t=0;
	#t=int(time/dt)+1;
	t=int(time/dt);
	return t;
}
function matchp(time,fromnode,srcport,tonode,dstport,attribute,value){
	rtn=0;
	if (time>=t_st && time<t_sp) {
		if ((p_time==""||p_time==time)&&(p_fromnode==""||p_fromnode==fromnode)&&(p_srcport==""||p_srcport==srcport)&&(p_tonode==""||p_tonode==tonode)&&(p_dstport==""||p_dstport==dstport)&&(p_attribute==""||p_attribute==attribute)&&(p_value==""||p_value==value)) {
			rtn=1;
		}
	}
	return rtn;
}
function output(p_attribute, prefix, array, array_n){
	last_avg_var=0;
	
	printf "\"%s%s\n",p_attribute, p_ct >> output_file;
        for ( i_t = 1; i_t <= maxt; i_t++ ) {
		if(array_n[i_t]>0){
			last_avg_var=array[i_t]/array_n[i_t];
		}
		print i_t*dt, prefix*last_avg_var >> output_file;
	}
	print "\n" >> output_file;
}
{
   time = $1;
   fromnode = $2;
   srcport = $3;
   tonode = $4;
   dstport = $5;
   attribute = $6;
   value = $7;
   
   t=get_t(dt, time);
   if(t > maxt){
	for (i_t = maxt+1; i_t <= t; i_t++){
		cwnd_[i_t]=0;
		cwnd_n[i_t]=0;
	}	
	maxt=t;
   }

   if (matchp(time,fromnode,srcport,tonode,dstport,attribute,value)==1){
	if(attribute == "cwnd_"){
		cwnd_n[t] = cwnd_n[t] + 1;
		cwnd_[t] = cwnd_[t] + value;
		#print time, attribute, value, t, cwnd_n[t], cwnd_[t];
	   }
	   if(attribute == "rtt_"){
		rtt_n[t] = rtt_n[t] + 1;
		rtt_[t] = rtt_[t] + value;
	   }
	   if(attribute == "srtt_"){
		srtt_n[t] = srtt_n[t] + 1;
		srtt_[t] = srtt_[t] + value;
	   }
	   if(attribute == "rttvar_"){
		rttvar_n[t] = rttvar_n[t] + 1;
		rttvar_[t] = rttvar_[t] + value;
	   }
	}
}						  
END {
	print "TitleText: leodos" >> output_file;
	print "Device: Postscript" >> output_file;
	
	output("cwnd_", 1, cwnd_, cwnd_n);
	output("rtt_", 100, rtt_, rtt_n);
	#output("srtt_", 100, srtt_, srtt_n);
	#output("rttvar_", 100, rttvar_, rttvar_n);
}
