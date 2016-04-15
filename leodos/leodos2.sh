#!/bin/bash

function clear_params_ns(){
	hp_n=25;# Maximum number of hops between two nodes in the original topology is 25
	bn_bw=5;#Bottleneck bandwidth is 1Mbps
	bn_dl=6;#Bottleneck delay is 5ms 
	bn_qs=50;#Bottleneck queue size 100
	bn_qm=1;#1 DropTail; 2 RED; 3 RED/PD; 4 Blue; 5 SFB; 6 CBQ; 7 FQ; 8 SFQ; 9 DRR; 10 PI; 11 Vq; 12 REM; 13 GK; 14 SRR; 15 RED/Robust; 16 SFB/Robust; 17 RED/PP; 18 DropTail/IIA;
	bn_tp=1;#1 dumbbell; 2 tree2;
	nt_bw=10;#Net bandwidth 10Mps
	nt_dl=2;#Net delay is 2ms

	ur_n=30;#5 normal users !! PackMimeHTTP max user number 10
	ur_cr=100;#Used for packmime http rate 10 new connetcions per second
	ur_ps=1000;#User flows packages size 1000B !!! to add
	ur_st=20;#User flows start at 20s
	ur_sp=240;#User flows stop at 240s
	ur_rs=0;#in ur_st-ur_sp, 0: users will not random start, 1: users will random start
	ur_pt=1;#User flows' type 1 is for TCP
	ur_app=0;#0: FTP, 1: Telnet, 2:PackMimeHTTP 3:PackMimeHTTP_DelayBox

	ak_n=20;#2 attackers
	ak_ng=20;#attackers divide into 1 group
	ak_tg=1000;#attackers' groups start time differeces
	ak_rs=0;#in a ak_ap 0: attackers will not random start, 1: attackers will random start
	ak_pr=5;#Attacker flows' packages rate 0.5Mbps
	ak_ps=50;#Attacker flows' packages size 200B
	ak_bp=200;#Attacker flows' burst period is 500ms
	ak_ap=20000;#Attacker flows' attack period is 1000ms
	ak_st=120;#Attacker flows start at 60s
	ak_sp=220;#Attacker flows stop at 100s
	ak_tp=1;#0: Flooding DDoS attacks 1: Low-rate DDoS attacks, 2: Follow tcp cwnd DDoS attack
	ak_mw=1;#for ak_tp 2 ak_nw is the max cwnd that correspond to ak_pr
	ak_cp=10;#Attacker flows' tcp cwnd check period is 10ms
	ak_spf_mn=1;#Attacker min spoof address is 1
	ak_spf_mx=60000;#Attacker max spoof address is 100
	ak_spf_lv=0;#Attacker address spoof level 0:no spoof 1:spoof


	tm_fi=240;#Simulation finishes at 120s
	ns_db=0;#0: do not output debug info, 1: output debug info
	ns_of=2;#ns output file ns_of >=3 o leodos.nam >=2 o leodos.tr leodos_tcp.tr leodos_queue_monitor.tr >=1 o leodos_queue.tr
}

function clear_params_awk(){
	#these variables are used in leodos_item.awk leodos_queue.awk
	p_tt="";
	p_dv="";
	p_ct="";
	p_rs="1";
	p_ml="";#whether output matlab data file
	p_ci="";#whether output c input data file

	m_fg="";#1:figure mode do not calculate

	dt="";
	s_l="";
	t_st="";
	t_sp="";

	d_cpr=0.3;#<d_cpr normal flow >=d_cpr DLDoS flow

	p_event="";
	p_time="";
	p_fromnode="";
	p_tonode="";
	p_pkttype=""
	p_pktsize="";
	p_flags="";
	p_fid="";
	p_srcaddr="";
	p_dstaddr=""
	p_seqnum="";
	p_pktid="";
	#for leodos_tcp.awk
	p_srcport="";
	p_dstport="";
	p_attribute="";
	p_value="";
}

function clear_params(){
	clear_params_ns;
	clear_params_awk;
}

function clear_static_file(){
	rm -f ./result/*.log;
	rm -f ./result/*.rs;
	rm -f ./result/*.m;
	rm -f ./result/*.ci;
	rm -f ./result/*.tmp;

}

function move_static_file(){
	mkdir "result/$1";
	mv result/*.log "result/$1";
	mv result/*.m "result/$1";
	mv result/*.rs "result/$1";	
}

function leodos_init(){
	clear_params;
	clear_static_file;
	
	sh_log_file="./result/leodos_sh.log";
	log_file="./result/leodos.log";
	tmp_file="./result/leodos.tmp";

	li=1;#the loop index to let inside loop know
	lj="";
}

function figure_queue(){
	awk -f leodos_queue.awk -v ur_n=$ur_n -v ak_n=$ak_n -v ur_st=$ur_st -v ur_sp=$ur_sp -v ak_st=$ak_st -v ak_sp=$ak_sp -v t_sp=$tm_fi -v p_rs=1  -v p_fromnode=$p_fromnode -v p_tonode=$p_tonode ./result/leodos_queue.tr;
	xgraph -bb -tk -x time -y pktcount ./result/leodos_queue.rs &
}

function do_params_awk(){
	params="-v bn_qs=$bn_qs -v ur_n=$ur_n -v ak_n=$ak_n -v ur_st=$ur_st -v ur_sp=$ur_sp -v ak_st=$ak_st -v ak_sp=$ak_sp -v t_sp=$tm_fi -v p_tt=$p_tt -v p_dv=$p_dv -v p_ct=$p_ct -v p_rs=$p_rs -v p_ml=$p_ml -v p_ci=$p_ci -v m_fg=$m_fg -v dt=$dt -v s_l=$s_l -v t_st=$t_st -v t_sp=$t_sp -v d_cpr=$d_cpr -v p_event=$p_event -v p_time=$p_time -v p_fromnode=$p_fromnode -v p_srcport=$p_srcport -v p_tonode=$p_tonode -v p_dstport=$p_dstport -v p_pkttype=$p_pkttype -v p_pktsize=$p_pktsize -v p_flags=$p_flags -v p_fid=$p_fid -v p_srcaddr=$p_srcaddr -v p_dstaddr=$p_dstaddr -v p_seqnum=$p_seqnum -v p_pktid=$p_pktid -v p_attribute=$p_attribute -v p_value=$p_value -v li=$li -v lj=$lj";
	sh_out="li=$li\n>>do_params_awk $1 $2\n params: $params\n";
	printf "$sh_out";printf "$sh_out" >> $sh_log_file;
	awk -f $1 $params $2;

}

function dosim(){
	params="-hp_n $hp_n -bn_bw $bn_bw -bn_dl $bn_dl -bn_qs $bn_qs -bn_qm $bn_qm -bn_tp $bn_tp -nt_bw $nt_bw -nt_dl $nt_dl -ur_n $ur_n -ur_cr $ur_cr -ur_ps $ur_ps -ur_st $ur_st -ur_sp $ur_sp -ur_rs $ur_rs -ur_pt $ur_pt -ur_app $ur_app -ak_n $ak_n -ak_ng $ak_ng -ak_tg $ak_tg -ak_rs $ak_rs -ak_pr $ak_pr -ak_ps $ak_ps -ak_bp $ak_bp -ak_ap $ak_ap -ak_st $ak_st -ak_sp $ak_sp -ak_tp $ak_tp -ak_mw $ak_mw -ak_cp $ak_cp -ak_spf_mn $ak_spf_mn -ak_spf_mx $ak_spf_mx -ak_spf_lv $ak_spf_lv -tm_fi $tm_fi -ns_db $ns_db -ns_of $ns_of -li $li";
	sh_out="li=$li\n>>dosim $1 $2\n params: $params\n";	
	printf "$sh_out";printf "$sh_out" >> $sh_log_file;
	if (( $2 == 2 ))
	then
		ns leodos2.tcl $params > $tmp_file;
	else
		ns leodos.tcl $params > $tmp_file;
	fi
	
	awk -f leodos_queue.awk -v ur_n=$ur_n -v ak_n=$ak_n -v ur_st=$ur_st -v ur_sp=$ur_sp -v ak_st=$ak_st -v ak_sp=$ak_sp -v t_sp=$tm_fi -v p_rs=$1 -v dt=$dt -v p_fromnode=$p_fromnode -v p_tonode=$p_tonode ./result/leodos_queue.tr >> $tmp_file;
	if (( $1 >= 1 ))
	then
		cat $tmp_file;
	fi
	cat $tmp_file >> $log_file;
	if (( $1 >= 2 ))
	then
		xgraph -bb -tk -x time -y pktcount ./result/leodos_queue.rs &
	fi
}

function trans_log(){
	i_log_file=$log_file
	o_log_file=$log_file

	if [[ $1 != "" ]]
	then
		i_log_file=$1
		o_log_file=$1
	fi
	
	if [[ $2 != "" ]]
	then
		o_log_file=$2
	fi
	
	awk -f leodos_trans_log.awk $i_log_file
	mv result/leodos_log.m "$o_log_file.m"
}

function task_item_awk(){	
	clear_static_file;
	clear_params_awk;

	p_tt="leodos";
	p_dv="Postscript";
	p_ml="1";
	dt=0.01;

	t_st=34;
	t_sp=39;

	p_ct="drop";
	p_event="d";
	p_fromnode=0;
	p_tonode=1;
	do_params_awk leodos_item.awk ./result/leodos.tr;

	#p_ct="attacker1";
	#p_event="r";
	#p_fromnode=12;
	#p_tonode=0;
	#do_params_awk leodos_item.awk ./result/leodos.tr;

	p_ct="user1";
	p_event="r";
	p_fromnode=8;
	p_tonode=0;
	do_params_awk leodos_item.awk ./result/leodos.tr;

	xgraph -bb -tk -x time -y pktcount ./result/leodos_item.rs &
}

function task_queue_awk(){	
	clear_static_file;
	clear_params_awk;

	p_tt="leodos";
	p_dv="Postscript";
	dt=0.01;
	t_st=24;
	t_sp=184;

	do_params_awk leodos_queue.awk ./result/leodos_queue.tr;

	xgraph -bb -tk -x time -y pktcount ./result/leodos_queue.rs &
}

function task_cpr_awk(){	
	clear_static_file;
	clear_params_awk;

	p_tt="leodos";
	p_dv="Postscript";
	p_ml="1";
	p_rs="1";
	t_st=0;
	t_sp=240;

	p_event="+";	
	p_fromnode=0;
	p_tonode=1;


	dt=0.01;
	s_l=0.01;
	p_ct="flows";
	do_params_awk leodos_cpr.awk ./result/leodos_queue.tr;

	xgraph -bb -tk -x time -y throughput ./result/leodos_cpr.rs &
}

function do_cpr(){
	t_st=0;
	t_sp=240;
	p_ml="1";	
       	p_rs="";
	p_ct="cpr_dred";
	do_params_awk leodos_cpr.awk ./result/leodos_queue.tr;
	#xgraph -bb -tk -x time -y pktcount ./result/leodos_cpr.rs &
}

function do_fftASD(){
	t_st=100;
	t_sp=240;
	p_ci="1";
	p_ml="";
	p_rs="";
	p_ct="sample";
	rm -f ./result/leodos_sample.*
	do_params_awk leodos_sample.awk ./result/leodos_queue.tr;		
	./leotools fftASD ./result/leodos_sample.ci ./result/leotools_fftASD.m
}

function loop_ak_pr(){
	ak_ng=1;
	ak_bp=200;
	ak_ap=1000;
	ak_pr=5;
	li=0;
	for ak_pr in 0.25 0.24 0.23 0.22 0.21 0.20 0.19 0.18 0.17 0.16 0.15 0.14 0.13 0.12 0.11 0.10 0.09 0.08 0.07 0.06 0.05 0.04 0.03 0.02 0.01
	do
		ak_tg=0;
		let li=li+1;
		dosim 0;
		#figure_queue;
		do_cpr;
		do_fftASD;
	done
	move_static_file "dred_ak_ng$ak_ng ak_bp$ak_bp ak_ap$ak_ap ak_pr0.25-0.01 countqueue";
}

function loop_ak_ap(){
	ak_ng=20;
	ak_bp=200;
	ak_ap=1000;
	ak_pr=5;
	li=0;	
	for ak_ap in 20000 21000 22000 23000 24000 25000 26000 27000 28000 29000 30000 31000 32000 33000 34000 35000 36000 37000 38000 39000 40000
	do
		ak_tg="$ak_ap/$ak_n";
		let li=li+1;
		dosim 0;
		#figure_queue;
		do_cpr;
		do_fftASD;
	done
	move_static_file "dred_ak_ng$ak_ng ak_bp$ak_bp ak_ap20-40 ak_pr$ak_pr countqueue";
}

function loop_ak_bp(){
	ak_ng=20;
	ak_bp=200;
	ak_ap=1000;
	ak_pr=5;
	li=0;
	for ak_bp in 10 9.5 9 8.5 8 7.5 7 6.5 6 5.5 5 4.5 4 3.5 3 2.5 2 1.5 1 0.5 0.1 
	do
		ak_tg=$ak_bp;
		let li=li+1;
		dosim 0;
		#figure_queue;
		do_cpr;
		do_fftASD;
	done
	move_static_file "dred_ak_ng$ak_ng ak_bp10-0.1 ak_ap$ak_ap ak_pr$ak_pr countqueue";
}

function loop_ak_rs(){
	ak_ng=10;
	ak_tg=1000;
	ak_bp=200;
	ak_ap=10000;
	ak_pr=2.5;
	ak_rs=1;
	li=1;
	while (($li<=100)) 
	do		
		dosim 0;
		#figure_queue;
		do_cpr;
		do_fftASD;
		let li=li+1;
	done
	move_static_file "dred_ak_ng$ak_ng ak_bp$ak_bp ak_ap$ak_ap ak_pr$ak_pr ak_rs$ak_rs countqueue";
}

function loop_cpr(){		
	clear_static_file;
	clear_params_awk;

	p_tt="leodos";
	p_dv="Postscript";
	p_ml="1";
	dt=0.001;
	s_l=0.001;

	p_event="+";	
	p_fromnode=0;
	p_tonode=1;
	p_ct="cpr_dred";

	ns_of=1;

	ur_n=30;#30 normal users
	ur_rs=1;
	ur_app=0;
	ak_n=20;#5 attackers
	ak_ng=5;
	ak_tg=1000;
	ak_bp=200;
	ak_ap=5000;
	ak_pr=1.25;
	ak_rs=0;
	li=0;
	for ak_ap in 500 1000 1500 2000 2500 3000 3500 4000 4500 5000 
	do
		for ak_bp in 25 50 75 100 125 150 175 200
		do
			for ak_pr in 0.75 1 1.25 1.5
			do
				ak_tg="$ak_ap/$ak_ng";
				let li=li+1
				dosim 0;
				do_cpr;
			done		
		done
	done
	move_static_file "dred_ak_ng$ak_ng ak_bp25-200 ak_ap500-5000 ak_pr0.75-1.5 ur_rs1 countqueue";
}

function task_sim_sample_uad(){
	clear_static_file;
	clear_params_awk;


	ur_n=30;
	ak_n=20;ak_ng=1;ak_tg=0;ak_rs=0;
	ak_pr=0.25;ak_ps=50;ak_bp=200;ak_ap=1000;

	ns_of=1;

	#dosim 0;
	#figure_queue;

	p_tt="leodos";
	p_dv="Postscript";
	p_rs="1";
	p_ml="1";
	p_ci="";
	dt=0.002;
	s_l=0.002;

	p_fromnode=0;
	p_tonode=1;

	t_st=34;
	t_sp=49;

	p_ct="usr_na";
	p_event="+";
	p_srcaddr="4.0";
	p_dstaddr="";
	p_fid="";
	do_params_awk leodos_sample.awk ./result/leodos_queue.tr;	

	p_ct="drop_na";
	p_event="d";
	p_srcaddr="*";
	p_dstaddr="*";
	p_fid="*";
	do_params_awk leodos_sample.awk ./result/leodos_queue.tr;	

	t_st=134;
	t_sp=149;

	p_ct="usr_a";
	p_event="+";
	p_srcaddr="4.0";
	p_dstaddr="";
	p_fid="";
	do_params_awk leodos_sample.awk ./result/leodos_queue.tr;	

	p_ct="atk";
	p_event="+";
	p_srcaddr="70.0";
	p_dstaddr="";
	p_fid="";
	do_params_awk leodos_sample.awk ./result/leodos_queue.tr;	

	p_ct="drop_a";
	p_event="d";
	p_srcaddr="*";
	p_dstaddr="*";
	p_fid="*";
	do_params_awk leodos_sample.awk ./result/leodos_queue.tr;

	xgraph -bb -tk -x time -y pktcount ./result/leodos_sample.rs &
	
	move_static_file "dred sim sample 0.002 uad ur_n$ur_n ak_n$ak_n ak_ng$ak_ng";
	
}

function task_sim_sample_cpr_awk(){	
	clear_static_file;
	clear_params_awk;

	ns_of=1;	
	#dosim 1;

	ur_n=30;#30 normal users
	ur_rs=0;
	ur_app=0;
	ak_n=20;#5 attackers

	p_tt="leodos";
	p_dv="Postscript";

	p_event="+";	
	p_fromnode=0;
	p_tonode=1;
	dt=0.001;
	s_l=0.001;


	#loop_ak_bp;	
	#loop_ak_pr;
	#loop_ak_ap;	
	loop_ak_rs;
}

function task_sample_figure(){
	clear_static_file;
	clear_params_awk;

	p_tt="leodos";
	p_dv="Postscript";
	p_rs="1";
	p_ml="";
	p_ci="";
	dt=0.01;
	s_l=0.01;

	p_fromnode=0;
	p_tonode=1;

	t_st=0;
	t_sp=240;

	#p_ct="leo_ddos";
	#p_event="+";
	#p_srcaddr="*";
	#p_dstaddr="*";
	#p_fid="*";
	#do_params_awk leodos_sample.awk ./result/leodos_queue.tr;

	p_ct="2to3";
	p_event="+";
	p_srcaddr="2.0";
	p_dstaddr="3.0";
	p_fid="";
	do_params_awk leodos_sample.awk ./result/leodos_queue.tr;

	p_ct="20to21";
	p_event="+";
	p_srcaddr="20.0";
	p_dstaddr="21.0";
	p_fid="";
	do_params_awk leodos_sample.awk ./result/leodos_queue.tr;

	p_ct="drop";
	p_event="d";
	p_srcaddr="*";
	p_dstaddr="*";
	p_fid="";
	do_params_awk leodos_sample.awk ./result/leodos_queue.tr;

	xgraph -bb -tk -x time -y pktcount ./result/leodos_sample.rs &	
}

function task_tcp_figure(){
	clear_static_file;
	clear_params_awk;
	t_st=0;
	t_sp=240;
	dt=0.01;

	p_ct="2to3";
	p_fromnode="2";
	p_srcport="";
	p_tonode="3";
	p_dstport="";
	p_attribute="";
	p_value="";	
	do_params_awk leodos_tcp.awk ./result/leodos_tcp.tr;

	p_ct="4to5";
	p_fromnode="4";
	p_srcport="";
	p_tonode="5";
	p_dstport="";
	p_attribute="";
	p_value="";	
	do_params_awk leodos_tcp.awk ./result/leodos_tcp.tr;

	p_ct="20to21";
	p_fromnode="20";
	p_srcport="";
	p_tonode="21";
	p_dstport="";
	p_attribute="";
	p_value="";	
	do_params_awk leodos_tcp.awk ./result/leodos_tcp.tr;


	xgraph -bb -tk -x time -y value ./result/leodos_tcp.rs &	
}

function loop_packmimehttp(){
	clear_static_file;
	clear_params_awk;

	ns_of=1;

	p_tt="leodos";
	p_dv="Postscript";
	p_rs="";
	p_ml="1";
	p_ci="";
	dt=0.001;
	s_l=0.001;
	
	p_event="+";	
	p_fromnode=0;
	p_tonode=1;

	t_st=0;
	t_sp=240;
	p_ct="cpr_dred_http";

	ur_n=10;#30 normal users
	ur_rs=0;
	ur_app=2;

	ak_n=10;#5 attackers
	ak_ng=5;
	ak_tg=1000;
	ak_bp=200;
	ak_ap=5000;
	ak_pr=2.5;
	ak_rs=0;

	li=1;
	ur_cr=10;
	while (($ur_cr <= 100)) 
	do
		dosim 0;	
		rm -f ./result/leodos_packmime.tr;
		do_params_awk leodos_trans_packmime.awk ./result/leodos_queue.tr;
		do_params_awk leodos_cpr.awk ./result/leodos_packmime.tr;		
		let li=li+1		
		let ur_cr=ur_cr+5
	done
	move_static_file "dred packmimehttp ur_cr5-150 countqueue";

}

function task_packmimehttp(){
	clear_static_file;
	clear_params_awk;

	ns_of=1;
	ur_app=2;

	ur_n=10;#30 normal users
	ur_rs=0;
	ur_app=2;

	ak_n=10;#5 attackers
	ak_ng=5;
	ak_tg=1000;
	ak_bp=200;
	ak_ap=5000;
	ak_pr=2.5;
	ak_rs=0;

	ur_cr=5;

	dosim 0 1;	
	#rm -f ./result/leodos_packmime.tr;
	#do_params_awk leodos_trans_packmime.awk ./result/leodos_queue.tr;

	p_tt="leodos";
	p_dv="Postscript";
	p_rs="1";
	p_ml="1";
	p_ci="";
	dt=0.01;
	s_l=0.01;

	m_fg="1";
	
	p_event="+";	
	p_fromnode=0;
	p_tonode=1;

	t_st=0;
	t_sp=240;
	p_ct="cpr_dred_http";
	do_params_awk leodos_cpr.awk ./result/leodos_packmime.tr;
	xgraph -bb -tk -x time -y value ./result/leodos_cpr.rs &
}

function dldos_realnet(){
	clear_static_file;
	clear_params_awk;


	ns_of=1;
	#dosim 0;
	

	p_tt="leodos";
	p_dv="Postscript";
	p_rs="";
	p_ml="1";
	
	#m_fg="1";

	p_event="+";	
	p_fromnode=0;
	p_tonode=1;
	dt=0.001;
	s_l=0.001;	

	#t_st=30;
	#t_sp=110;
	#p_ct="cpr_dred";
	#do_params_awk leodos_cpr.awk ./result/leodos_queue.tr;

	#t_st=130;
	#t_sp=210;
	#p_ct="cpr_dred";
	#do_params_awk leodos_cpr.awk ./result/leodos_queue.tr;

	ur_n=12;
	ak_n=4;	

	p_ct="cpr_real";

	ur_st=0;
	ur_sp=69;
	ak_st=35;
	ak_sp=48;

	t_st=$ur_st;
	t_sp=$ak_st;
	do_params_awk leodos_cpr.awk ./result/RL_dldos1m.tr;
	t_st=$ak_st;
	t_sp=$ak_sp;
	do_params_awk leodos_cpr.awk ./result/RL_dldos1m.tr;
	t_st=$ur_st;
	t_sp=$ur_sp;
	do_params_awk leodos_cpr.awk ./result/RL_dldos1m.tr;
	mv ./result/leodos_cpr.m ./result/RL_dldos1m.m 

	ur_st=0;
	ur_sp=75;
	ak_st=44.7;
	ak_sp=56.6;

	t_st=$ur_st;
	t_sp=$ak_st;
	do_params_awk leodos_cpr.awk ./result/RL_dldos2m.tr;
	t_st=$ak_st;
	t_sp=$ak_sp;
	do_params_awk leodos_cpr.awk ./result/RL_dldos2m.tr;
	t_st=$ur_st;
	t_sp=$ur_sp;
	do_params_awk leodos_cpr.awk ./result/RL_dldos2m.tr;
	mv ./result/leodos_cpr.m ./result/RL_dldos2m.m 

	ur_st=0;
	ur_sp=76;
	ak_st=42.1;
	ak_sp=54.3;

	t_st=$ur_st;
	t_sp=$ak_st;
	do_params_awk leodos_cpr.awk ./result/RL_dldos4m.tr;
	t_st=$ak_st;
	t_sp=$ak_sp;
	do_params_awk leodos_cpr.awk ./result/RL_dldos4m.tr;
	t_st=$ur_st;
	t_sp=$ur_sp;
	do_params_awk leodos_cpr.awk ./result/RL_dldos4m.tr;
	mv ./result/leodos_cpr.m ./result/RL_dldos4m.m 

	move_static_file "dred real network";

	#xgraph -bb -tk -x time -y value ./result/leodos_cpr.rs &
}

function task_aqms(){
	#clear_static_file;
	clear_params_awk;
	#1 For DropTail; 2 For RED; 3 For RED-PD; 4 For Blue; 5 For SFB
	ns_of=1;
	
	for bn_qm in 1 2 3 4 5 6 7 8 9 10 11 12 13 14
	do
		dosim 0;
		#clear_static_file;
		#figure_queue;
	done
}

function loop_ak_n_aqm(){
	li=1;
	for ak_n in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30
	do
		ak_ng=$ak_n;
		dosim 0;		
		let li=li+1
	done
	mv $log_file "$log_file.ak_n.log"
	mv $sh_log_file "$sh_log_file.ak_n.log"
}

function loop_ak_ap_aqm(){
	li=1;
	for ak_ap in 200 300 400 500 600 700 800 900 1000 1100 1200 1300 1400 1500 1600 1700 1800 1900 2000
	do
		dosim 0;		
		let li=li+1
	done
	mv $log_file "$log_file.ak_ap.log"
	mv $sh_log_file "$sh_log_file.ak_ap.log"
}

function loop_ak_bp_aqm(){
	li=1;
	for ak_bp in 0 20 40 60 80 100 120 140 160 180 200 220 240 260 280 300 320 340 360 380 400 420 440 460 480 500 520 540 560 580 600
	do
		dosim 0;		
		let li=li+1
	done
	mv $log_file "$log_file.ak_bp.log"
	mv $sh_log_file "$sh_log_file.ak_bp.log"
}

function loop_ak_pr_aqm(){
	li=1;
	#for ak_pr in 0.1 0.125 0.15 0.175 0.2 0.225 0.25 0.275 0.3 0.325 0.35 0.375 0.4 0.425 0.45  0.475 0.5
	for ak_pr in 0 0.025 0.05 0.075 0.1 0.125 0.15 0.175 0.2 0.225 0.25 0.275 0.3 0.325 0.35 0.375 0.4 0.425 0.45  0.475 0.5
	do
		dosim 0;		
		let li=li+1
	done
	mv $log_file "$log_file.ak_pr.log"
	mv $sh_log_file "$sh_log_file.ak_pr.log"
}

function task_aqm_ldos(){
	#bn_qm 1 DropTail; 2 RED; 3 RED/PD; 4 Blue; 5 SFB 6 CBQ 7 FQ; 8 SFQ; 9 DRR; 10 PI; 11 Vq; 12 REM; 13 GK; 14 SRR 15 RED/Robust;
	bn_qm=15;
	ak_spf_mn=100;#Attacker min spoof address is 1
	ak_spf_mx=60000;#Attacker max spoof address is 100
	ak_spf_lv=0;
	ak_n=20;
	ur_n=30;
	ns_of=1;

	#Rb
	#for bn_qm in 15 2 3 5 11 1
	for bn_qm in 5
	do
		clear_static_file;
		#ak_n=20;ak_ng=20;ak_tg=0;ak_rs=0;ak_pr=0.25;ak_ps=50;ak_bp=200;ak_ap=1000;
		#loop_ak_n_aqm;
		#ak_n=20;ak_ng=20;ak_tg=0;ak_rs=0;ak_pr=0.25;ak_ps=50;ak_bp=200;ak_ap=1000;
		#loop_ak_ap_aqm;
		ak_n=20;ak_ng=20;ak_tg=0;ak_rs=0;ak_pr=0.25;ak_ps=50;ak_bp=200;ak_ap=1000;
		loop_ak_bp_aqm;
		#ak_n=20;ak_ng=20;ak_tg=0;ak_rs=0;ak_pr=0.25;ak_ps=50;ak_bp=200;ak_ap=1000;
		#loop_ak_pr_aqm;
		#move_static_file "AQM_$bn_qm";		
	done
	
#	task_trans_aqm_log;
}

function task_rred_http(){
	#bn_qm 1 DropTail; 2 RED; 3 RED/PD; 4 Blue; 5 SFB 6 CBQ 7 FQ; 8 SFQ; 9 DRR; 10 PI; 11 Vq; 12 REM; 13 GK; 14 SRR 15 RED/Robust;
	bn_qm=15;
	ur_n=10;
	ak_n=20;ak_ng=20;ak_tg=0;ak_rs=0;ak_pr=0.25;ak_ps=50;ak_bp=200;ak_ap=1000;
	ns_of=1;

	ur_cr=1000;
	ur_app=2;

	ur_st=20;
	ur_sp=35;
	ak_st=25;
	ak_sp=30;
	tm_fi=35;

	clear_static_file;
	li=1;
	for ur_cr in 100 200 300 400 500 600 700 800 900 1000
	do
		dosim -1;
		#figure_queue;
		rm -f ./result/leodos_packmime.tr;
		do_params_awk leodos_trans_packmime.awk ./result/leodos_queue.tr;
		awk -f leodos_queue.awk -v ur_n=$ur_n -v ak_n=$ak_n -v ur_st=$ur_st -v ur_sp=$ur_sp -v ak_st=$ak_st -v ak_sp=$ak_sp  -v t_sp=$tm_fi -v p_rs=  ./result/leodos_packmime.tr
		let li=li+1
	done	
}

function trans_aqm_log(){
	rm $1/*.m;
	#trans_log "$1/leodos.log.ak_ap.log";
	#trans_log "$1/leodos.log.ak_bp.log";
	#trans_log "$1/leodos.log.ak_n.log";
	trans_log "$1/leodos.log.ak_pr.log";
}

function task_trans_aqm_log(){
	trans_aqm_log "result/AQM_1";
	trans_aqm_log "result/AQM_2";
	trans_aqm_log "result/AQM_3";
	trans_aqm_log "result/AQM_5";
	trans_aqm_log "result/AQM_11";
	trans_aqm_log "result/AQM_15";
}

function task_trans_aqm_log_sfdos(){
	trans_aqm_log "result/AQM_sfdos_16";
	trans_aqm_log "result/AQM_sfdos_2";
	trans_aqm_log "result/AQM_sfdos_5";
	trans_aqm_log "result/AQM_sfdos_1";
	trans_aqm_log "result/AQM_sfdos_3";
}

function task_aqm_spoof_ddos(){
	#bn_qm 1 DropTail; 2 RED; 3 RED/PD; 4 Blue; 5 SFB 6 CBQ 7 FQ; 8 SFQ; 9 DRR; 10 PI; 11 Vq; 12 REM; 13 GK; 14 SRR 15 RED/Robust 16 SFB/Robust;
	bn_qm=15;
	ak_spf_mn=100;#Attacker min spoof address is 1
	ak_spf_mx=60000;#Attacker max spoof address is 100
	ak_spf_lv=1;
	ak_n=20;
	ur_n=30;
	ns_of=1;

	#Rb
	for bn_qm in 16 2 5 1 3
	do
		clear_static_file;
		ak_n=20;ak_ng=20;ak_tg=0;ak_rs=0;ak_pr=0.25;ak_ps=50;ak_bp=1000;ak_ap=1000;
		loop_ak_pr_aqm;
		move_static_file "AQM_sfdos_$bn_qm";		
	done
	
	task_trans_aqm_log_sfdos;
}

function task_spoof(){
	#1 DropTail; 2 RED; 3 RED/PD; 4 Blue; 5 SFB 6 CBQ 7 FQ; 8 SFQ;	9 DRR; 10 PI; 11 Vq; 12 REM; 13 GK; 14 SRR 15 RED/Robust 16 SFB/Robust;
	bn_qm=15;
	ak_spf_mn=100;#Attacker min spoof address is 1
	ak_spf_mx=60000;#Attacker max spoof address is 100
	ak_spf_lv=1;
	ak_n=1;
	ur_n=30;
	ns_of=1;

	p_fromnode=0;
	p_tonode=1;

	#Rb
	for bn_qm in 1 16
	do
		ak_n=20;ak_ng=1;ak_tg=0;ak_rs=0;ak_pr=0.25;ak_ps=50;ak_bp=1000;ak_ap=1000;
		clear_static_file;
		dosim 0 1;		
		figure_queue;
	done
}

function task_leodos_mbn2_verify(){
	clear_static_file;
	clear_params_awk;
	ns_of=1;ns_db=0;bn_qm=1;bn_qs=50;
	
	ur_st=10;ur_sp=40;ak_st=20;ak_sp=30;tm_fi=50;
	#ur_st=5;ur_sp=35;ak_st=15;ak_sp=25;tm_fi=40;
	ur_n=30;ur_app=0;
	ak_n=20;ak_ng=1;ak_tg=0;ak_rs=0;ak_pr=0.25;ak_ps=50;ak_bp=1000;ak_ap=1000

	ak_spf_mn=100;#Attacker min spoof address is 1
	ak_spf_mx=60000;#Attacker max spoof address is 100
	ak_spf_lv=1;

	p_fromnode='';
	p_tonode='';
	dosim 0 2;
	p_fromnode=1;
	p_tonode=0;
	do_params_awk leodos_queue.awk ./result/leodos_queue.tr;
	p_fromnode=4;
	p_tonode=1;
	do_params_awk leodos_queue.awk ./result/leodos_queue.tr;
}

function task_mbn_rsfb(){
	clear_static_file;
	clear_params_awk;
	ns_of=1;ns_db=0;bn_qm=16;bn_qs=50;
	
	ur_st=10;ur_sp=40;ak_st=20;ak_sp=30;tm_fi=50;
	#ur_st=5;ur_sp=35;ak_st=15;ak_sp=25;tm_fi=40;
	ur_n=30;ur_app=0;
	ak_n=20;ak_ng=1;ak_tg=0;ak_rs=0;ak_pr=0.25;ak_ps=50;ak_bp=1000;ak_ap=1000;

	ak_spf_mn=100;#Attacker min spoof address is 1
	ak_spf_mx=60000;#Attacker max spoof address is 100
	ak_spf_lv=1;

	#p_fromnode=4;
	#p_tonode=1;
	dosim 0 2;

	p_fromnode=1;
	p_tonode=0;
	do_params_awk leodos_queue.awk ./result/leodos_queue.tr;

	p_fromnode=2;
	p_tonode=0;
	do_params_awk leodos_queue.awk ./result/leodos_queue.tr;

	p_fromnode=3;
	p_tonode=1;
	do_params_awk leodos_queue.awk ./result/leodos_queue.tr;	

	p_fromnode=4;
	p_tonode=1;
	do_params_awk leodos_queue.awk ./result/leodos_queue.tr;

	p_fromnode=5;
	p_tonode=2;
	do_params_awk leodos_queue.awk ./result/leodos_queue.tr;	

	p_fromnode=6;
	p_tonode=2;
	do_params_awk leodos_queue.awk ./result/leodos_queue.tr;
}

function task_mbn_cpr(){
	clear_static_file;
	clear_params_awk;
	ns_of=1;ns_db=0;bn_qm=2;bn_tp=2;bn_qs=50;
	
	ur_st=10;ur_sp=40;ak_st=20;ak_sp=30;tm_fi=50;
	ur_n=30;ur_app=0;
	ak_n=20;ak_ng=1;ak_tg=0;ak_rs=0;ak_ps=50;ak_bp=200;ak_ap=1000;ak_pr=0.25;

	ak_spf_mn=100;#Attacker min spoof address is 1
	ak_spf_mx=60000;#Attacker max spoof address is 100
	ak_spf_lv=0;

	#p_fromnode=4;
	#p_tonode=1;
	#dosim 0 2;

	p_ct="mbn";t_st=15;t_sp=35;dt=0.001;s_l=0.001;p_ml="1";

	li=1;
	for ak_bp in 0 20 40 60 80 100 120 140 160 180 200 220 240 260 280 300 320 340 360 380 400 420 440 460 480 500 520 540 560 580 600
	do
		p_fromnode='';p_tonode='';dosim 0 2;		
		lj=1;p_fromnode=1;p_tonode=0;do_params_awk leodos_cpr.awk ./result/leodos_queue.tr;
		lj=2;p_fromnode=2;p_tonode=0;do_params_awk leodos_cpr.awk ./result/leodos_queue.tr;
		lj=3;p_fromnode=3;p_tonode=1;do_params_awk leodos_cpr.awk ./result/leodos_queue.tr;
		lj=4;p_fromnode=4;p_tonode=1;do_params_awk leodos_cpr.awk ./result/leodos_queue.tr;
		lj=5;p_fromnode=5;p_tonode=2;do_params_awk leodos_cpr.awk ./result/leodos_queue.tr;
		lj=6;p_fromnode=6;p_tonode=2;do_params_awk leodos_cpr.awk ./result/leodos_queue.tr;
		let li=li+1
	done
	move_static_file "mbn_cpr_tb";

	ak_bp=200;ak_ap=1000;ak_pr=0.25;
	li=1;
	for ak_pr in 0 0.025 0.05 0.075 0.1 0.125 0.15 0.175 0.2 0.225 0.25 0.275 0.3 0.325 0.35 0.375 0.4 0.425 0.45  0.475 0.5
	do
		p_fromnode='';p_tonode='';dosim 0 2;
		lj=1;p_fromnode=1;p_tonode=0;do_params_awk leodos_cpr.awk ./result/leodos_queue.tr;
		lj=2;p_fromnode=2;p_tonode=0;do_params_awk leodos_cpr.awk ./result/leodos_queue.tr;
		lj=3;p_fromnode=3;p_tonode=1;do_params_awk leodos_cpr.awk ./result/leodos_queue.tr;
		lj=4;p_fromnode=4;p_tonode=1;do_params_awk leodos_cpr.awk ./result/leodos_queue.tr;
		lj=5;p_fromnode=5;p_tonode=2;do_params_awk leodos_cpr.awk ./result/leodos_queue.tr;
		lj=6;p_fromnode=6;p_tonode=2;do_params_awk leodos_cpr.awk ./result/leodos_queue.tr;
		let li=li+1
	done
	move_static_file "mbn_cpr_rb";
}

function task_dos_rsfb(){
	clear_static_file;
	clear_params_awk;
	ns_of=1;ns_db=0;bn_qm=5;bn_qs=50;
	
	ur_st=10;ur_sp=40;ak_st=20;ak_sp=30;tm_fi=50;
	ur_n=30;ur_app=0;
	ak_n=20;ak_ng=1;ak_tg=0;ak_rs=0;ak_ps=50;ak_bp=1000;ak_ap=1000;ak_pr=0.25;

	ak_spf_mn=100;ak_spf_mx=60000;ak_spf_lv=0;

	p_ct="mbn";t_st=10;t_sp=40;dt=0.001;s_l=0.001;p_ml="";p_rs="";
	bn_tp=1;p_fromnode=0;p_tonode=1;
	#for bn_qm in 16 1 2 5 3
	for bn_qm in 16
	do
		for ak_spf_lv in 0 1
		do
			li=1;#for ak_pr in 0.45 0.5
			#for ak_pr in 0 0.05 0.1 0.15 0.2 0.25 0.3 0.35 0.4 0.45 0.5
			for ak_pr in 0.05 0.1 0.15 0.2 0.25 0.3 0.35 0.4 0.45 0.5						
			do
				dosim 0 2;
				let li=li+1
			done
			mv $log_file "$log_file.spf$ak_spf_lv.log"
			trans_log "$log_file.spf$ak_spf_lv.log";
			mv $sh_log_file "$sh_log_file.spf$ak_spf_lv.log"
		done
		#move_static_file "dos_sbn2_$bn_qm";
	done

	#bn_tp=2;
	#for bn_qm in 16 1 2 5 3	
	#do
	#	for ak_spf_lv in 0 1
	#	do
	#		li=1;
	#		for ak_pr in 0.05 0.25 0.5			
	#		do
	#			p_fromnode='';p_tonode='';dosim 0 2;
	#			lj=1;p_fromnode=1;p_tonode=0;do_params_awk leodos_queue.awk ./result/leodos_queue.tr > $tmp_file;cat $tmp_file;cat $tmp_file >> $log_file;
	#			lj=2;p_fromnode=2;p_tonode=0;do_params_awk leodos_queue.awk ./result/leodos_queue.tr > $tmp_file;cat $tmp_file;cat $tmp_file >> $log_file;
	#			lj=3;p_fromnode=3;p_tonode=1;do_params_awk leodos_queue.awk ./result/leodos_queue.tr > $tmp_file;cat $tmp_file;cat $tmp_file >> $log_file;
	#			lj=4;p_fromnode=4;p_tonode=1;do_params_awk leodos_queue.awk ./result/leodos_queue.tr > $tmp_file;cat $tmp_file;cat $tmp_file >> $log_file;
	#			lj=5;p_fromnode=5;p_tonode=2;do_params_awk leodos_queue.awk ./result/leodos_queue.tr > $tmp_file;cat $tmp_file;cat $tmp_file >> $log_file;
	#			lj=6;p_fromnode=6;p_tonode=2;do_params_awk leodos_queue.awk ./result/leodos_queue.tr > $tmp_file;cat $tmp_file;cat $tmp_file >> $log_file;
	#			let li=li+1
	#		done			
	#		move_static_file "dos_mbn2_$bn_qm.spf$ak_spf_lv";
	#	done
	#done
}

function task_iia_nam(){
	clear_params;
	bn_bw=5;bn_dl=2;bn_qs=50;bn_qm=18;bn_tp=13;nt_bw=2;nt_dl=2;
	ur_n=10;ur_ps=1000;ur_st=1;ur_sp=11;ur_pt=1;ur_app=0;
	ak_n=5;ak_ng=1;ak_tg=0;ak_rs=0;ak_pr=1.0;ak_ps=50;ak_bp=100;ak_ap=100;ak_st=4;ak_sp=8;ak_tp=0;ak_spf_lv=0;
	tm_fi=12;ns_db=3;ns_of=3;
	
	p_fromnode=4;p_tonode=6;dt=0.04;
	
	#bn_qm=1;dosim 2 2;
	#mv "./result/leodos_queue.rs" "./result/leodos_queue_dt.rs"
	bn_qm=18;dosim 2 2;
	#mv "./result/leodos_queue.rs" "./result/leodos_queue_iia.rs"
}

function loop_ak_pr_iia(){
	li=1;
	for ak_pr in 0 0.2 0.4 0.6 0.8 1.0 1.2 1.4 1.6 1.8 2
	do
		dosim 0 2;	
		let li=li+1
	done
	mv $log_file "$log_file.$bn_tp.$bn_qm.log"
	mv $sh_log_file "$sh_log_file.$bn_tp.$bn_qm.log"
	trans_log "$log_file.$bn_tp.$bn_qm.log"
}

function loop_ak_li_iia(){
	li=1;
	while (($li <= 100)) 
	do
		dosim 0 2;
		let li=li+1
	done
	mv $log_file "$log_file.$bn_tp.$bn_qm.log"
	mv $sh_log_file "$sh_log_file.$bn_tp.$bn_qm.log"
}

function task_iia(){
	clear_params;
	bn_bw=5;bn_dl=2;bn_qs=50;bn_qm=18;bn_tp=13;nt_bw=2;nt_dl=2;
	ur_n=10;ur_ps=1000;ur_st=1;ur_sp=11;ur_pt=1;ur_app=0;
	ak_n=5;ak_ng=1;ak_tg=0;ak_rs=0;ak_pr=1;ak_ps=50;ak_bp=100;ak_ap=100;ak_st=4;ak_sp=8;ak_tp=0;ak_spf_lv=0;
	tm_fi=12;ns_db=3;ns_of=1;
	
	p_fromnode=4;p_tonode=6;
	
	ak_rs=0;
	
	bn_tp=11;bn_qm=1;loop_ak_pr_iia;
	bn_tp=11;bn_qm=18;loop_ak_pr_iia;
	move_static_file "remote-atk-ak_pr";
	
	bn_tp=12;bn_qm=1;loop_ak_pr_iia;
	bn_tp=12;bn_qm=18;loop_ak_pr_iia;
	move_static_file "local-atk-ak_pr";
	
	bn_tp=13;bn_qm=1;loop_ak_pr_iia;
	bn_tp=13;bn_qm=18;loop_ak_pr_iia;
	move_static_file "heterogeneous-atk-ak_pr";
	

	#ak_rs=1;ak_pr=1;
	
	#bn_tp=11;bn_qm=1;loop_ak_li_iia;
	#bn_tp=11;bn_qm=18;loop_ak_li_iia;
	#bn_tp=12;bn_qm=1;loop_ak_li_iia;
	#bn_tp=12;bn_qm=18;loop_ak_li_iia;
	#bn_tp=13;bn_qm=1;loop_ak_li_iia;
	#bn_tp=13;bn_qm=18;loop_ak_li_iia;
	#trans_log;move_static_file "random-atk";
}

function main(){
	leodos_init;
	
	task_iia_nam;
	#task_iia;
	
}

main;

#loop_awk "fft_sample_length";
#loop_awk "fft_dt";
#dosim 1;
#task_item_awk;
#task_queue_awk;
#loop_sim_cpr;
#task_one;
#task_sim_sample_cpr_awk;
#figure_queue;
#loop_cpr;
#task_sim_sample_uad;
#task_sample_figure;
#task_packmimehttp;
#loop_packmimehttp;
#dosim 1;
#task_tcp_figure;
#task_cpr_awk;
#dldos_realnet;
#task_aqm_ldos;
#task_spoof;
#task_aqm_spoof_ddos;
#task_trans_aqm_log_sfdos;
#task_rred_http;
#task_one;
#task_spoof;
#task_mbn_rsfb;
#task_leodos_mbn_verify;
#task_leodos_mbn2_verify;
#task_mbn_cpr;
#task_dos_rsfb;
#task_aldos;
