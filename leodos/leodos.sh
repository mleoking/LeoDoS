#!/bin/bash

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

bn_bw=5;#Bottleneck bandwidth is 5Mbps
bn_dl=6;#Bottleneck delay is 6ms 
bn_qs=50;#Bottleneck queue size 50
bn_qm=1;#1 DropTail; 2 RED; 3 RED/PD; 4 Blue; 5 SFB 6 CBQ 7 FQ; 8 SFQ;	9 DRR; 10 PI; 11 Vq; 12 REM; 13 GK; 14 SRR 15 RED/Robust 16 SFB/Robust;
nt_bw=10;#Net bandwidth 10Mbps
nt_dl=2;#Net delay is 2ms
hp_n=25;# Maximum number of hops between two nodes in the original topology is 25. This parameter is not used in the current version of the simulation platform

#The experimental network has a dumbbell topology as the network experimented in the RRED algorithm (Zhang, 2010).
#        Users                       
#            \                                  
#             Router0---Router1---Server
#            /                        
#        Attackers

ur_n=30;#30 normal users !! PackMimeHTTP max user number 10
ur_cr=100;#Used for packmime, http rate 100 new connections per second
ur_ps=1000;#User flows packages size 1000B !!! to add
ur_st=20;#User flows start at 20s
ur_sp=240;#User flows stop at 240s
ur_rs=0;#in ur_st-ur_sp, 0: users will not random start, 1: users will random start
ur_pt=1;#User flows' type 1 is for TCP
ur_app=0;#The application of normal user traffic 0: FTP, 1: Telnet, 2:PackMimeHTTP 3:PackMimeHTTP_DelayBox

ak_n=20;#20 attackers
ak_ng=1;#attackers divide into 1 group. Most of the time, you do not need to change the value of this parameter.
ak_tg=0;#attackers' groups start time differeces. Most of the time, you do not need to change the value of this parameter.
ak_rs=0;#in a ak_ap 0: attackers will not random start, 1: attackers will random start
ak_pr=0.25;#Attacker flows' packages rate 0.25Mbps
ak_ps=50;#Attacker flows' packages size 50B
ak_bp=200;#Attacker flows' burst period is 200ms
ak_ap=1000;#Attacker flows' attack period is 1000ms
ak_st=120;#Attacker flows start at 120s
ak_sp=220;#Attacker flows stop at 220s
ak_tp=1;#1:represents period attack, 2:represents follow tcp cwnd attack
ak_mw=1;#for ak_tp 2 ak_nw is the max cwnd that correspond to ak_pr
ak_cp=10;#Attacker flows' tcp cwnd check period is 10ms
ak_spf_mn=1;#Attacker min spoof address is 1
ak_spf_mx=60000;#Attacker max spoof address is 100
ak_spf_lv=0;#Attacker address spoof level 0:no spoof 1:spoof


tm_fi=240;#Simulation finishes at 240s
ns_db=0;#0: do not output debug info, 1: output debug info
ns_of=2;#ns output file ns_of >=3 o leodos.nam >=2 o leodos.tr leodos_tcp.tr leodos_queue_monitor.tr >=1 o leodos_queue.tr

sh_log_file="./result/leodos_sh.log";
log_file="./result/leodos.log";
tmp_file="./result/leodos.tmp";


#rm -f $log_file
rm -f $tmp_file

li=1;#the loop index to let inside loop know

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

function clear_params_awk(){
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
#[t_st,t_sp)

d_cpr=0.3;

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

function do_params_awk(){
	params="-v bn_qs=$bn_qs -v ur_n=$ur_n -v ak_n=$ak_n -v ur_st=$ur_st -v ur_sp=$ur_sp -v ak_st=$ak_st -v ak_sp=$ak_sp -v p_tt=$p_tt -v p_dv=$p_dv -v p_ct=$p_ct -v p_rs=$p_rs -v p_ml=$p_ml -v p_ci=$p_ci -v m_fg=$m_fg -v dt=$dt -v s_l=$s_l -v t_st=$t_st -v t_sp=$t_sp -v d_cpr=$d_cpr -v p_event=$p_event -v p_time=$p_time -v p_fromnode=$p_fromnode -v p_srcport=$p_srcport -v p_tonode=$p_tonode -v p_dstport=$p_dstport -v p_pkttype=$p_pkttype -v p_pktsize=$p_pktsize -v p_flags=$p_flags -v p_fid=$p_fid -v p_srcaddr=$p_srcaddr -v p_dstaddr=$p_dstaddr -v p_seqnum=$p_seqnum -v p_pktid=$p_pktid -v p_attribute=$p_attribute -v p_value=$p_value -v li=$li";
	sh_out="li=$li\n>>do_params_awk $1 $2\n params: $params\n";
	printf "$sh_out";printf "$sh_out" >> $sh_log_file;
	awk -f $1 $params $2;
}

function dosim(){
	params="-hp_n $hp_n -bn_bw $bn_bw -bn_dl $bn_dl -bn_qs $bn_qs -bn_qm $bn_qm -nt_bw $nt_bw -nt_dl $nt_dl -ur_n $ur_n -ur_cr $ur_cr -ur_ps $ur_ps -ur_st $ur_st -ur_sp $ur_sp -ur_rs $ur_rs -ur_pt $ur_pt -ur_app $ur_app -ak_n $ak_n -ak_ng $ak_ng -ak_tg $ak_tg -ak_rs $ak_rs -ak_pr $ak_pr -ak_ps $ak_ps -ak_bp $ak_bp -ak_ap $ak_ap -ak_st $ak_st -ak_sp $ak_sp -ak_tp $ak_tp -ak_mw $ak_mw -ak_cp $ak_cp -ak_spf_mn $ak_spf_mn -ak_spf_mx $ak_spf_mx -ak_spf_lv $ak_spf_lv -tm_fi $tm_fi -ns_db $ns_db -ns_of $ns_of -li $li";
	sh_out="li=$li\n>>dosim $1\n params: $params\n";	
	printf "$sh_out";printf "$sh_out" >> $sh_log_file;
	ns leodos.tcl $params > $tmp_file;
	awk -f leodos_queue.awk -v ur_n=$ur_n -v ak_n=$ak_n -v ur_st=$ur_st -v ur_sp=$ur_sp -v ak_st=$ak_st -v ak_sp=$ak_sp -v t_sp=$tm_fi -v p_rs=  ./result/leodos_queue.tr >> $tmp_file;
	cat $tmp_file;
	cat $tmp_file >> $log_file;
	if (($1==1))
	then
		awk -f leodos.awk ./result/leodos.tr >> $tmp_file;
		cat $tmp_file;
		cat $tmp_file >> $log_file;
		xgraph -bb -tk -x x -y y ./result/leodos.rs &
		rm -f ./result/leodos_tcp.rs;
		awk -f leodos_tcp.awk  ./result/leodos_tcp.tr;
		xgraph -bb -tk -x x -y y ./result/leodos_tcp.rs &
	fi
}

function figure_queue(){
	awk -f leodos_queue.awk -v ur_n=$ur_n -v ak_n=$ak_n -v ur_st=$ur_st -v ur_sp=$ur_sp -v ak_st=$ak_st -v ak_sp=$ak_sp -v t_sp=$tm_fi -v p_rs=1  ./result/leodos_queue.tr;
	xgraph -bb -tk -x time -y pktcount ./result/leodos_queue.rs &
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
	for ak_pr in 0.1 0.125 0.15 0.175 0.2 0.225 0.25 0.275 0.3 0.325 0.35 0.375 0.4 0.425 0.45 0.475 0.5
	do
		dosim 0;
		let li=li+1
	done
	mv $log_file "$log_file.ak_pr.log"
	mv $sh_log_file "$sh_log_file.ak_pr.log"
}

function task_aqm_ldos(){	
	ak_n=20;
	ur_n=30;
	ns_of=1;

	bn_qm=$1;
	clear_static_file;
	#Experiment set one: Ta =[0.2, 2], Tb=200 and Rb=0.25
	ak_n=20;ak_rs=0;ak_ps=50;ak_bp=200;ak_ap=1000;ak_pr=0.25;
	loop_ak_ap_aqm;
	#Experiment set two: Ta =1, Tb=[0, 600] and Rb=0.25
	ak_n=20;ak_rs=0;ak_ps=50;ak_bp=200;ak_ap=1000;ak_pr=0.25;
	loop_ak_bp_aqm;
	#Experiment set three: Ta =1, Tb=200 and Rb=[0.1, 0.5]
	ak_n=20;ak_rs=0;ak_ps=50;ak_bp=200;ak_ap=1000;ak_pr=0.25;
	loop_ak_pr_aqm;
	move_static_file "AQM_$bn_qm";
}

dosim 0; #Conduct a single simulation using the parameters specified in the head of this file.

#"task_aqm_ldos x;" represents a batch of experiments on AQM x. 
#If you want to experiment on a specific AQM, please remove the # before its line and execute the leodos.sh:

#task_aqm_ldos 2; #RED
#task_aqm_ldos 3; #RED-PD
#task_aqm_ldos 11; #AVQ
#task_aqm_ldos 1; #DropTail

#note: The SFB and RRED experiment commands below is only available after you have successfully integrating them into your ns2 distributions.
#task_aqm_ldos 5; #SFB
#task_aqm_ldos 15; #Roubust RED

#x is the number of the AQM algorithm. The mapping of x to AQM algorithms is:
#1 DropTail; 2 RED; 3 RED/PD; 4 Blue; 5 SFB 6 CBQ 7 FQ; 8 SFQ;	9 DRR; 10 PI; 11 Vq; 12 REM; 13 GK; 14 SRR 15 RED/Robust 16 SFB/Robust;

#The results of these experiments are recorded in the output files whose names begin with "AQM_x" in a style shown in Appendix 1 of "readme.txt". 
