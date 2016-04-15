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

# ======================================================================
# Default Script Parameters
# ======================================================================
set pam(hp_n)	25;# Maximum number of hops between two nodes in the original topology is 25
set pam(bn_bw)	1;#Bottleneck bandwidth is 1Mbps
set pam(bn_dl) 5;#Bottleneck delay is 5ms 
set pam(bn_qs) 100;#Bottleneck queue size 100
set pam(bn_qm) 1;#1 DropTail; 2 RED; 3 RED/PD; 4 Blue; 5 SFB 6 CBQ 7 FQ; 8 SFQ;	9 DRR; 10 PI; 11 Vq; 12 REM; 13 GK; 14 SRR 15 RED/Robust 16 SFB/Robust;
set pam(nt_bw) 10;#Net bandwidth 10Mps
set pam(nt_dl) 2;#Net delay is 2ms

set pam(ur_n) 2;#2 normal users
set pam(ur_cr) 10;#Used for packmime http rate 10 new connetcions per second
set pam(ur_ps) 1000;#User flows packages size 1000B !!! to add
set pam(ur_st) 20;#User flows start at 20s
set pam(ur_sp) 120;#User flows stop at 120s
set pam(ur_rs) 0;#in ur_st-ur_sp, 0: users will not random start, 1: users will random start
set pam(ur_pt) 1;#User flows' type 1 for TCP
set pam(ur_app) 0;# 0: FTP, 1: Telnet, 2:PackMimeHTTP 3:PackMimeHTTP_DelayBox

set pam(ak_n) 2;#2 attackers
set pam(ak_ng) 1;#attackers divide into 1 group
set pam(ak_tg) 0;#attackers' groups start time differeces
set pam(ak_rs) 0;#in a ak_ap 0: attackers will not random start, 1: attackers will random start
set pam(ak_pr) 0.5;#Attacker flows' packages rate 0.5Mbps
set pam(ak_ps) 200;#Attacker flows' packages size 200B
set pam(ak_bp) 500;#Attacker flows' burst period is 500ms
set pam(ak_ap) 1000;#Attacker flows' attack period is 1000ms
set pam(ak_st) 60;#Attacker flows start at 60s
set pam(ak_sp) 100;#Attacker flows stop at 100s
set pam(ak_tp) 2;#1:represents period attack, 2:represents follow tcp cwnd attack
set pam(ak_mw) 5;#for ak_tp 2 ak_nw is the max cwnd that correspond to ak_pr
set pam(ak_cp) 10;#Attacker flows' tcp cwnd check period is 10ms
set pam(ak_spf_mn) 1;#Attacker min spoof address is 1
set pam(ak_spf_mx) 100;#Attacker max spoof address is 100
set pam(ak_spf_lv) 0;#Attacker address spoof level 0:no spoof 1:spoof

set pam(tm_fi) 120;#Simulation finishes at 120s
set pam(ns_db) 0;#0: do not output debug info, 1: output debug info
set pam(ns_of) 3;#ns output file ns_of >=3 o leodos.nam >=2 o leodos.tr leodos_tcp.tr leodos_queue_monitor.tr >=1 o leodos_queue.tr
set pam(li) 0;#the loop index
# ======================================================================

proc usage {} {
    global argv0
	
    puts "\nusage: $argv0 \[-hp_n hp_n\] \[-bn_bw bn_bw\] \[-bn_dl bn_dl\] \[-bn_qs bn_qs\] \[-nt_bw nt_bw\] \[-nt_dl nt_dl\] \n              \[-ur_n ur_n\] \[-ur_cr ur_cr\] \[-ur_ps ur_ps\] \[-ur_st ur_st\] \[-ur_sp ur_sp\] \[-ur_rs ur_rs\] \[-ur_pt tcp|udp\] \[-ur_app ur_app\]\n              \[-ak_n ak_n\] \[-ak_ng ak_ng\] \[-ak_tg ak_tg\] \[-ak_rs ak_rs\] \[-ak_pr ak_pr\] \[-ak_ps ak_ps\] \[-ak_bp ak_bp\] \[-ak_ap ak_ap\] \[-ak_st ak_st\] \[-ak_sp ak_sp\] \[-ak_tp ak_tp\] \[-ak_mw ak_mw\] \[-ak_cp ak_cp\]\n              \[-tm_fi tm_fi\] \[-ns_db ns_db\] \[-ns_of ns_of\] \[-li li\]\n"
}

proc printPam {} {
	global pam
	foreach pami [array names pam] {
		puts "$pami\t$pam($pami)";
	}
	#puts ""
}

proc getPam {argc argv} {
	global pam

	for {set i 0} {$i < $argc} {incr i} {
		set arg [lindex $argv $i]
		if {[string range $arg 0 0] != "-"} continue

		set name [string range $arg 1 end]
		set pam($name) [lindex $argv [expr $i+1]]
		set pam($name) [expr $pam($name)]
	}
}

proc ceilDivide {n1 n2} {	
	set n1dn2 [expr $n1/$n2]
	if {[expr $n1dn2*$n2<$n1]} {
		set n1dn2 [expr $n1dn2+1];
	}
	return $n1dn2;
}

proc bottomDivide {n1 n2} {	
	set n1dn2 [expr $n1/$n2]
	return $n1dn2;
}

proc equal {n1 n2} {
	set rtnval 0
	set d12 [expr $n1-$n2]
	if {$d12<0} {
		set d12 [expr -$d12]
	}
	if {$d12<0.0001} {
		set rtnval 1
	}
	return $rtnval
}

proc setAtkSendRate {apAtkSendID agUsrSendID} {
	global ns pam agUsrSend apAtkSend
	set usrSendCwnd [$agUsrSend($agUsrSendID) set cwnd_]
	set nsnow [$ns now]
	set atkSendRate 0			
	if {$usrSendCwnd>$pam(ak_mw)} {
		set atkSendRate [expr $pam(ak_pr)]
		#puts "nsnow:$nsnow usrSendCwnd:$usrSendCwnd atkSendRate:$atkSendRate"
	} else {
		#set atkSendRate [expr $pam(ak_pr)*$usrSendCwnd/$pam(ak_mw).0]
		set atkSendRate 0.0001
	}
	set apAtkSendRateNow [expr [$apAtkSend($apAtkSendID) set rate_]/1000000.0]
	#puts "apAtkSendRateNow:$apAtkSendRateNow"
	if {[equal $apAtkSendRateNow $atkSendRate]!=1} {
		puts "nsnow:$nsnow usrSendCwnd:$usrSendCwnd apAtkSendRateNow:$apAtkSendRateNow atkSendRate:$atkSendRate"
		$apAtkSend($apAtkSendID) set rate_ [expr $atkSendRate]Mb
	}
}

proc setAtkSendState {apAtkSendID agUsrSendID} {
	global ns pam agUsrSend apAtkSend lastAtkSendState
	set usrSendCwnd [$agUsrSend($agUsrSendID) set cwnd_]
	set nsnow [$ns now]
	set atkSendRate 0
	if {$lastAtkSendState($apAtkSendID) == 0 && $usrSendCwnd>=$pam(ak_mw)} {
		$apAtkSend($apAtkSendID) start	
		set lastAtkSendState($apAtkSendID) 1
		puts "nsnow:$nsnow 0->1"
	}
	if {$lastAtkSendState($apAtkSendID) == 1 && $usrSendCwnd<$pam(ak_mw)} {
		$apAtkSend($apAtkSendID) stop		
		set lastAtkSendState($apAtkSendID) 0
		puts "nsnow:$nsnow 1->0"
	}
}

proc monitorFlow {prob} {
    global redpdflowmon_ redpdq_
    #puts "monitorFlow redpdflowmon_:$redpdflowmon_ redpdq_:$redpdq_"
    foreach flow [$redpdflowmon_ flows] {
    	#monitor the flow with probability $prob
	$redpdq_ monitor-flow $flow $prob 
    }	
}

proc unmonitorFlow {} {
    global redpdflowmon_ redpdq_
    #puts "unmonitorFlow redpdflowmon_:$redpdflowmon_ redpdq_:$redpdq_"
    foreach flow [$redpdflowmon_ flows] {
	#unmonitor the flow
	$redpdq_ unmonitor-flow $flow 
    }	
}

proc finish {} {
	global ns allTF namTF tcpTF queueTF queueMonitorTF
	$ns flush-trace
	close $allTF
	close $namTF
	close $tcpTF
	close $queueTF
	close $queueMonitorTF
	exit 0 
}

set ns [new Simulator]

#usage
getPam $argc $argv
printPam

Queue/RED set bytes_ false ;
Queue/RED set queue_in_bytes_ false ;
#Queue/RED set adaptive_ 0 ;

# Added by leoking RobustRed config 0
Queue/RED/Robust set hash_bins_ 23
Queue/RED/Robust set hash_levels_ 2
Queue/RED/Robust set score_max_ 10
Queue/RED/Robust set score_min_ -1
Queue/RED/Robust set score_pass_ 0
Queue/RED/Robust set last_drop_time_ 0ms
Queue/RED/Robust set drop_related_period_ 10ms
# Added by leoking RobustRed config 1

Agent/TCP set minrto_ 1;

set rng [new RNG]

#Set Trace
set allTF [open ./result/leodos.tr w]
if { $pam(ns_of) >=2 } {
	$ns trace-all $allTF;
}
set namTF [open ./result/leodos.nam w]
if { $pam(ns_of) >=3 } {
	$ns namtrace-all $namTF
}

set tcpTF [open ./result/leodos_tcp.tr w]


#Set Nam
$ns color 2 red

#Create Topo Bottle Nodes
if {$pam(ur_app) == 2 || $pam(ur_app) == 3 } {
	remove-all-packet-headers
	add-packet-header IP TCP
	$ns use-scheduler Heap

	global defaultRNG
       # $defaultRNG seed 9999
	set PM [new PackMimeHTTP]

	if { $pam(ur_app) == 2 } {
		set nBotSend [$ns node] 
		set nBotRecv [$ns node] 
	}

	if { $pam(ur_app) == 3 } {
		#Trace set show_tcphdr_ 1 
		set nBotSend [$ns DelayBox] 
		set nBotRecv [$ns DelayBox] 
	   
		# create random variables
		set srcd_rng [new RNG];
		set src_delay [new RandomVariable/Uniform];   # delay 20-50 ms
		$src_delay set min_ 20
		$src_delay set max_ 50
		$src_delay use-rng $srcd_rng
	
		set srcbw_rng [new RNG];
		set src_bw [new RandomVariable/Uniform];      # bw 1-20 Mbps
		$src_bw set min_ 1
		$src_bw set max_ $pam(nt_bw)
		$src_delay use-rng $srcbw_rng
	
		set sinkd_rng [new RNG];
		set sink_delay [new RandomVariable/Uniform];   # delay 1-20 ms
		$sink_delay set min_ 1
		$sink_delay set max_ 20
		$sink_delay use-rng $sinkd_rng
	
		set sinkbw_rng [new RNG];
		set sink_bw [new RandomVariable/Constant];      # bw 100 Mbps
		$sink_bw set val_ $pam(nt_bw)
		$sink_bw use-rng $sinkbw_rng
	
		set loss_rng [new RNG];
		set loss_rate [new RandomVariable/Uniform];    # loss 0-1%
		$loss_rate set min_ 0
		$loss_rate set max_ 0.01
		$loss_rate use-rng $loss_rng
	}
}

if {$pam(ur_app) == 0 || $pam(ur_app) == 1} {
	set nBotSend [$ns node] 
	set nBotRecv [$ns node] 
}

#1 For DropTail; 2 For RED; 3 For RED-PD; 4 For Blue; 5 For SFB
set bn_qms "DropTail";
if {$pam(bn_qm)==1} {
	set bn_qms "DropTail";	
}
if {$pam(bn_qm)==2} {
	set bn_qms "RED";	
}
if {$pam(bn_qm)==3} {
	set bn_qms "RED/PD";	
}
if {$pam(bn_qm)==4} {
	set bn_qms "Blue";	
}
if {$pam(bn_qm)==5} {
	set bn_qms "SFB";	
}
if {$pam(bn_qm)==6} {
	set bn_qms "CBQ";	
}
if {$pam(bn_qm)==7} {
	set bn_qms "FQ";	
}
if {$pam(bn_qm)==8} {
	set bn_qms "SFQ";	
}
if {$pam(bn_qm)==9} {
	set bn_qms "DRR";	
}
if {$pam(bn_qm)==10} {
	set bn_qms "PI";	
}
if {$pam(bn_qm)==11} {
	set bn_qms "Vq";	
}
if {$pam(bn_qm)==12} {
	set bn_qms "REM";	
}
if {$pam(bn_qm)==13} {
	set bn_qms "GK";	
}
if {$pam(bn_qm)==14} {
	set bn_qms "SRR";	
}
if {$pam(bn_qm)==15} {
	set bn_qms "RED/Robust";	
}
if {$pam(bn_qm)==16} {
	set bn_qms "SFB/Robust";	
}
puts "bn_qms\t$bn_qms";

#$ns duplex-link $nBotSend $nBotRecv $pam(bn_bw)Mb $pam(bn_dl)ms $bn_qms
$ns simplex-link $nBotSend $nBotRecv $pam(bn_bw)Mb $pam(bn_dl)ms $bn_qms
$ns simplex-link $nBotRecv $nBotSend $pam(bn_bw)Mb $pam(bn_dl)ms DropTail

$ns queue-limit $nBotSend $nBotRecv $pam(bn_qs)
$ns queue-limit $nBotRecv $nBotSend $pam(bn_qs)
set bnQueue [[$ns link $nBotSend $nBotRecv] queue]

#set redpdlink_ ""
#set redpdq_ ""
#set redpdflowmon_ ""

if {$pam(bn_qm)==3} {
    set redpdlink_ [$ns link $nBotSend $nBotRecv]
    set redpdq_ [$redpdlink_ queue]
    set redpdflowmon_ [$redpdq_ makeflowmon $redpdlink_]

    #puts "initial redpdflowmon_:$redpdflowmon_ redpdq_:$redpdq_"

    $ns at $pam(ur_st)+0.01 "monitorFlow 0.1"
    $ns at $pam(ak_st)+0.01 "monitorFlow 0.1"
    #$ns at $pam(ur_sp)-20 "unmonitorFlow"
}

set nRecv [$ns node] 
$ns duplex-link $nRecv $nBotRecv $pam(nt_bw)Mb $pam(nt_dl)ms DropTail

#User Flows
for {set i 0} {$i < $pam(ur_n)} {incr i} { 
	#Create Topo
	set nUsrSend($i) [$ns node] 
	#!!! need random
	#$ns duplex-link $nUsrSend($i) $nBotSend $pam(nt_bw)Mb $pam(nt_dl)ms DropTail
	$ns duplex-link $nUsrSend($i) $nBotSend $pam(nt_bw)Mb $pam(nt_dl)ms DropTail
	
	if {$pam(ur_app) == 1 || $pam(ur_app)==0} {
		#Attach Agent
		set agUsrSend($i) [new Agent/TCP/Newreno] 
		$ns attach-agent $nUsrSend($i) $agUsrSend($i) 
		if { $pam(ur_app)==0} {
			set apUsrSend($i) [new Application/FTP] 
		}
		if { $pam(ur_app)==1} {
			set apUsrSend($i) [new Application/Telnet] 
		}	
		$apUsrSend($i) attach-agent $agUsrSend($i) 
		set agUsrRecv($i) [new Agent/TCPSink] 
		$ns attach-agent $nRecv $agUsrRecv($i) 
		$ns connect $agUsrSend($i) $agUsrRecv($i)
		$agUsrSend($i) set class_ 1 
		
		#Tcp Trace
		if { $pam(ns_of) >=2 } {
			$agUsrSend($i) attach $tcpTF
			$agUsrSend($i) trace cwnd_
			$agUsrSend($i) trace rtt_ 
			$agUsrSend($i) trace srtt_ 
			$agUsrSend($i) trace rttvar_
		}
	
		#Set Application Paramter
		$agUsrSend($i) set packetSize_ $pam(ur_ps)
		#$agUsrSend($i) set minrto_ 1
	
		#Schedule !!! need random 
		set dit 0;
		if {$pam(ur_rs) == 1} {
			set dit [integer [expr $pam(ur_sp)-$pam(ur_st)]];
		}
		if {$pam(ns_db)==1} {
			set nsnow [$ns now];
			set ap_st [expr $pam(ur_st)+$dit];
			puts "nsnow:$nsnow at $ap_st apUsrSend($i) start";
		}
		$ns at [expr $pam(ur_st)+$dit] "$apUsrSend($i) start"
		$ns at $pam(ur_sp) "$apUsrSend($i) stop"
	}

	if {$pam(ur_app) == 2 || $pam(ur_app) == 3} {
		# HTTP
		if { $pam(ur_app) == 3 } {
			# setup rules for DelayBoxes
			$nBotSend add-rule [$nUsrSend($i) id] [$nRecv id] $src_delay $loss_rate $src_bw
			$nBotRecv add-rule [$nUsrSend($i) id] [$nRecv id] $sink_delay $loss_rate $sink_bw
		}
		# set server and client	
		$PM set-server $nRecv
		$PM set-client $nUsrSend($i)

	}
	
}


#Attacker FLows
if {$pam(ak_n) > 0 && $pam(ak_ng) > 0 && $pam(ak_pr) > 0 && $pam(ak_ps) > 0 && $pam(ak_bp) > 0 && $pam(ak_ap) > 0} {
	set ak_ngm [expr $pam(ak_n)/$pam(ak_ng)];#number of member per group
	#set ak_dtg [expr $pam(ak_ap)/$pam(ak_ng)/1000.0];
	set ak_dtg [expr $pam(ak_tg)/1000.0];#the start time difference between each group
	for {set i 0} {$i < $pam(ak_n)} {incr i} { 
		#Create Topo
		set nAtkSend($i) [$ns node]
		#!!! need modify
		#$ns duplex-link $nAtkSend($i) $nBotSend $pam(nt_bw)Mb $pam(nt_dl)ms DropTail
		$ns duplex-link $nAtkSend($i) $nBotSend $pam(nt_bw)Mb $pam(nt_dl)ms DropTail
	
		#Set Nam
		$nAtkSend($i) color red
		$nAtkSend($i) shape square
		
		#Attach Agent
		set agAtkSend($i) [new Agent/UDP]
		$ns attach-agent $nAtkSend($i) $agAtkSend($i) 
		set apAtkSend($i) [new Application/Traffic/CBR]
		$apAtkSend($i) attach-agent $agAtkSend($i) 
	
		set agAtkRecv($i) [new Agent/Null] 
		$ns attach-agent $nRecv $agAtkRecv($i)
		$ns connect $agAtkSend($i) $agAtkRecv($i)
		$agAtkSend($i) set class_ 2 
		
		if {$pam(ak_spf_lv) > 0} {	
			#Spoof config , this code need agent-leo.h/cc and necessary modification in udp.h/cc and tcp.h/cc
			$agAtkSend($i) set saddr_min_ $pam(ak_spf_mn)
			$agAtkSend($i) set saddr_max_ $pam(ak_spf_mx)
			$agAtkSend($i) set spoof_level_ $pam(ak_spf_lv)
			#$agAtkSend($i) print-leoinfo
		}
		
		#Set Application Paramter	
		$apAtkSend($i) set packet_size_ $pam(ak_ps)
		
		#Schedule
		if {$pam(ak_tp) == 1} {
			$apAtkSend($i) set rate_ $pam(ak_pr)Mb
			#Loop for period attack
			set ak_ig [bottomDivide $i $ak_ngm];
			for {set it [expr $pam(ak_st)+$ak_ig*$ak_dtg]} {$it < $pam(ak_sp)} {set it [expr $it+$pam(ak_ap)/1000.0]} { 
				set dit 0;				
				if {$pam(ak_rs) == 1} {
					set rndint 0;
					if {$pam(ak_ap)>$pam(ak_bp)} {
						set rndint [integer [expr $pam(ak_ap)-$pam(ak_bp)]];
					} else {
						set rndint [integer [expr $pam(ak_ap)]];
					}					
					set dit [expr $rndint/1000.0];
				}
				$ns at [expr $it+$dit] "$apAtkSend($i) start";
				$ns at [expr $it+$dit+$pam(ak_bp)/1000.0] "$apAtkSend($i) stop";
				if {$pam(ns_db)==1} {
					set nsnow [$ns now];
					puts "nsnow:$nsnow it:$it dit:$dit i:$i start";
					puts "nsnow:$nsnow it:$it dit:$dit +$pam(ak_bp)/1000.0 i:$i stop";
				}
				
			}
		}
	
		if {$pam(ak_tp) == 2} {
			$apAtkSend($i) set rate_ $pam(ak_pr)Mb
			#$ns at $pam(ak_st) "$apAtkSend($i) start"
			set lastAtkSendState($i) 0
			#Loop for follow tcp cwnd attack
			for {set it $pam(ak_st)} {$it < $pam(ak_sp)} {set it [expr $it+$pam(ak_cp)/1000.0]} { 
				#setAtkSendState $i 0
				$ns at $it "setAtkSendState $i $i"
			}
			$ns at $pam(ak_sp) "$apAtkSend($i) stop"
		}
	
	}
}

if {$pam(ur_app) == 2 || $pam(ur_app) == 3} {
	$PM set-outfile "./result/leodos_http.tr"
	$PM set-rate $pam(ur_cr)
	$PM set-1.1
	$PM set-TCP Newreno

        $ns at $pam(ur_st) "$PM start"
        $ns at $pam(ur_sp) "$PM stop"
}

#Set Queue Trace
set queueTF [open ./result/leodos_queue.tr w]
if { $pam(ns_of) >=1 } {
	$ns trace-queue $nBotSend $nBotRecv $queueTF;
	#$ns trace-queue $nBotRecv $nBotSend $queueTF;
}
set queueMonitor [new QueueMonitor]
set queueMonitor [$ns monitor-queue $nBotSend $nBotRecv $queueMonitor 0.01]
set queueMonitorTF [open ./result/leodos_queue_monitor.tr w]
if { $pam(ns_of) >=2 } {
	$queueMonitor trace $queueMonitorTF;
}

$ns at $pam(tm_fi) "finish"
$ns run
