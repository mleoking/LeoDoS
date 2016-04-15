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

-----------------------------------------------------------------------------------------------------------------------------------
  AQM&DoS Simulation Platform is mainly tested on ns-2.33, but it is expected to be compatible with higher versions of ns.
  If you are using a different version of ns, please replace "2.33" with the version number of your ns in all the following instructions.
-----------------------------------------------------------------------------------------------------------------------------------

This document helps to install the AQM&DoS Simulatino Platform and conduct experiments on DoS attacks and AQM algorithms.
To experiment on the AQM&DoS Simulatino Platform, you should fellow these steps:
1. Unzip the package of the AQM&DoS Simulation Platform in your Linux system (the subdirectory "result" is necesary to output the simulation result, you should keep it) and run the following command in the directory "aqm-dos-sim-plat".
	chmod +x leodos.sh
2. Install the ns-allinone-2.33 (or higher version) simulation software in your operation system.
	NS-2.33: http://sourceforge.net/projects/nsnam/files/allinone/ns-allinone-2.33/ns-allinone-2.33.tar.gz/download
	Note1: AQM&DoS Simulation Platform is tested on ns-2.33, but it is expected to be compatible with higher versions of ns.
	Note2: AWK is also required to run the platform. But most users do not need to manually install it as it is already included in most Linux distributions. If it is not included in your Linux system, you can refer to the following link to install it.
	AWK: http://www.gnu.org/software/gawk/
	Or if you are using Debian or Ubuntu Linux, you can use the following two commands to install AWK:
	1. sudo apt-get install gawk
	2. cd /usr/bin/ && sudo ln -s gawk awk
3. Integrate RRED into your NS2 distribution.
	Please follow the instruction in "ns2-integration\integration-of-rred.txt"
4. Modify simulation settings in "leodos.sh" to conduct your specified experiments.
	You need to modify the parameters in the "leodos.sh" to conduct a variety of simulations. 
	4.1 The following line of code means to conduct a single simulation using the parameters specified in the head of "leodos.sh":
			dosim 0;
	4.2 The following line of code means to conduct a batch of simulations on a specified AQM algorithm x:
			"task_aqm_ldos x;"		
		x is the number of the AQM algorithm. The mapping of x to AQM algorithms is:
		1 DropTail; 2 RED; 3 RED/PD; 4 Blue; 5 SFB 6 CBQ 7 FQ; 8 SFQ;	9 DRR; 10 PI; 11 Vq; 12 REM; 13 GK; 14 SRR 15 RED/Robust 16 SFB/Robust;
		If you want to experiment on a specific AQM algorithm, please remove the # before its line.		
	The original setting of the "leodos.sh" is to conduct a single simulation.
	You might need to understand and modify the logic of the function "task_aqm_ldos" to conduct your own batch of simulations.		
5. Run the simulations using the following command in the directory "aqm-dos-sim-plat".
	./leodos.sh
	The experimental results are located in the sub-directory "result", including:
 		1. The overall trace file "leodos.tr"
		2. The TCP trace file "leodos_tcp.tr"
		3. The queue monitor trace file "leodos_queue_monitor.tr"
		4. The bottleneck queue trace file "leodos_queue.tr"
		5. The nam trace file "leodos.nam" (To get the nam trace file, you need to change the value of "ns_of" from 2 to 3 in "leodosh.sh")
		6. The log files "leodos.log" and "leodos_sh.log". "leodos.log" records the parameters of each simulation and its statistical results in a format shown in Appendix 1. If you run a batch of simulations using "task_aqm_ldos", these log files will be located in a sub-directory named "AQM_x" (x is the number of the AQM algorithm) under "result".

Optional steps:	
o1. Integrate the ip spoofing function into your NS2 distribution (Do this step only if you need to simulate spoofing DDoS attacks).
	Please follow the instruction in "ns2-integration\integration-of-ip-spoofing.txt"
o2. Integrate SFB/blue into your NS2 distribution (Do this step only if you need to simulate SFB).
	Please follow the instruction (README) in "ns2-integration\ns2-blue.tar.gz" - the code and instruction of SFB/blue.
o3. Integrate RSFB (Resilient Stochastic Fair Blue) into your NS2 distribution (Do this step only if you need to simulate RSFB and have finished the step o2).
	Please follow the instruction in "ns2-integration\integration-of-rsfb.txt"
	
The experimental results of Robust Random Early Detection (RRED) algorithm in [1] are also included in the "result" subdirectory. They are "aqm_ak_pr.m", "aqm_ak_ap.m", and "aqm_ak_bp.m", which are all Matlab script file. You can get figures in Figure 4 in our paper [1] by executing these files in Matlab. In these Matlab script files, array "rate_f1_attack_*" records the rate of TCP traffic under LDoS attacks for AQM *. The statistic data used for plotting Figure 4 in our paper are also record in these "rate_f1_attack_*" arrays.

References:
1. Changwang Zhang, Jianping Yin, Zhiping Cai, and Weifeng Chen, RRED: Robust RED Algorithm to Counter Low-rate Denial-of-Service Attacks, IEEE Communications Letters, vol. 14, pp. 489-491, 2010.

Notes: 
	If you have any problem in doing these experiments, please contract us. mleoking@gmail.com



Appendix 1:
The results of these experiments are something like this:

ak_spf_mx	60000
nt_dl	2
ur_sp	240
ak_st	120
ur_cr	100
ur_n	30
li	1
ns_of	1
ak_spf_lv	0
ak_bp	200
ak_pr	0.25
bn_qm	15
ur_st	20
ak_spf_mn	100
ak_ps	50
tm_fi	240
ak_tp	1
ur_app	0
ak_rs	0
ak_ng	20
bn_bw	5
ak_n	20
ur_ps	1000
ur_pt	1
nt_bw	10
ur_rs	0
bn_qs	50
ak_ap	200
hp_n	25
ns_db	0
ak_cp	10
ak_sp	220
ak_tg	0
ak_mw	1
bn_dl	6
bn_qms	RED/Robust
leodos_queue_awk: dt=0.010000 s_l=0.000000 t_st=0.000000 t_sp=240.000000 ur_n=30 ak_n=20 ur_st=20.000000 ur_sp=240.000000 ak_st=120.000000 ak_sp=220.000000 p_ct=pktcount 
rate_f1_normal  600.680000      rate_f1_attack  597.220000      nth_f1  0.994240        rate_f2_attack  17.940000

From line "ak_spf_mx" to line "bn_qms" are detailed parameters of this experiment (please refer to leodos.sh for the meaning of these parameters). The followed lines are statistic results. We focus on the statistic results. 
In the results:
 "rate_f1_normal" depicts the average throughput rate (packets/s) of normal TCP traffic through the bottleneck link when there is no DoS/LDoS attack.
 "rate_f1_attack" depicts the average throughput rate (packets/s) of normal TCP traffic through the bottleneck link when an DoS/LDoS attack is attacking (from ak_st to ak_sp).
 "nth_f1" represents the preserved ratio of normal TCP traffic throughput under a DoS/LDoS attack, which equals to rate_f1_attack/rate_f1_normal.
 "rate_f2_attack" depicts the average throughput rate (packets/s) of attack traffic through the bottleneck link when an DoS/LDoS attack is attacking (from ak_st to ak_sp).
