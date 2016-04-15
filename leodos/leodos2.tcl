# ======================================================================
# Default Script Parameters
# ======================================================================
set pam(hp_n)	25;# Maximum number of hops between two nodes in the original topology is 25
set pam(bn_bw)	1;#Bottleneck bandwidth is 1Mbps
set pam(bn_dl) 5;#Bottleneck delay is 5ms 
set pam(bn_qs) 100;#Bottleneck queue size 100
set pam(bn_qm) 1;#1 DropTail; 2 RED; 3 RED/PD; 4 Blue; 5 SFB; 6 CBQ; 7 FQ; 8 SFQ; 9 DRR; 10 PI; 11 Vq; 12 REM; 13 GK; 14 SRR; 15 RED/Robust; 16 SFB/Robust; 17 RED/PP; 18 DropTail/IIA;
set pam(bn_tp) 1;#1 dumbbell; 2 tree2;
set pam(nt_bw) 10;#Net bandwidth 10Mps
set pam(nt_dl) 2;#Net delay is 2ms

set pam(ur_n) 2;#5 normal users
set pam(ur_cr) 10;#Used for packmime http rate 10 new connetcions per second
set pam(ur_ps) 1000;#User flows packages size 1000B !!! to add
set pam(ur_st) 20;#User flows start at 20s
set pam(ur_sp) 120;#User flows stop at 120s
set pam(ur_rs) 0;#in ur_st-ur_sp, 0: users will not random start, 1: users will random start
set pam(ur_pt) 1;#User flows' type 1 for TCP
set pam(ur_app) 0;# 0: FTP, 1: Telnet, 2:PackMimeHTTP (The maximum number of client and server are all 10 and they must be equal) 3:PackMimeHTTP_DelayBox (The maximum number of client and server are all 10 and they must be equal)

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
set pam(ak_tp) 1;#0: Flooding DDoS attacks 1: Low-rate DDoS attacks, 2: Follow tcp cwnd DDoS attack
set pam(ak_mw) 5;#for ak_tp 2 ak_nw is the max cwnd that correspond to ak_pr
set pam(ak_cp) 10;#Attacker flows' tcp cwnd check period is 10ms
set pam(ak_spf_mn) 1;#Attacker min spoof address is 1
set pam(ak_spf_mx) 100;#Attacker max spoof address is 100
set pam(ak_spf_lv) 0;#Attacker address spoof level 0:no spoof 1:spoof

set pam(tm_fi) 120;#Simulation finishes at 120s
set pam(ns_db) 0;#0: do not output debug info, 1: output basic debug info 2: output detailed debug info
set pam(ns_of) 3;#ns output file ns_of >=3 o leodos.nam >=2 o leodos.tr leodos_tcp.tr leodos_queue_monitor.tr >=1 o leodos_queue.tr
set pam(li) 0;#the loop index i
#set pam(lj) 0;#the loop index j
# ======================================================================

set bnlNnow 0;
set usrNnow 0;
set atkNnow 0;

global defaultRNG
$defaultRNG seed 0

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

proc setAtkSendState {apAtkID agUsrID} {
	global ns pam agUsr apAtk lastAtkSendState
	set usrSendCwnd [$agUsr($agUsrID) set cwnd_]
	set nsnow [$ns now]
	set atkSendRate 0
	if {$lastAtkSendState($apAtkID) == 0 && $usrSendCwnd>=$pam(ak_mw)} {
		$apAtk($apAtkID) start	
		set lastAtkSendState($apAtkID) 1
		puts "nsnow:$nsnow 0->1"
	}
	if {$lastAtkSendState($apAtkSendID) == 1 && $usrSendCwnd<$pam(ak_mw)} {
		$apAtk($apAtkID) stop		
		set lastAtkSendState($apAtkID) 0
		puts "nsnow:$nsnow 1->0"
	}
}

proc monitorFlow {prob} {
	global ns pam bnQueueFlowmon bnQueue

	foreach ibnQueue [array names bnQueue] {
		if {$pam(ns_db)>=2} {
			set nsnow [$ns now]
			puts "$nsnow monitorFlow bnQueueFlowmon($ibnQueue):$bnQueueFlowmon($ibnQueue) bnQueue($ibnQueue):$bnQueue($ibnQueue)"
		}

		foreach flow [$bnQueueFlowmon($ibnQueue) flows] {		
		    	#monitor the flow with probability $prob
			$bnQueue($ibnQueue) monitor-flow $flow $prob 
		}	
	}
}

proc unmonitorFlow {} {
	global ns pam bnQueueFlowmon bnQueue

	foreach ibnQueue [array names bnQueue] {
		if {$pam(ns_db)>=2} {
			set nsnow [$ns now]
			puts "$nsnow monitorFlow bnQueueFlowmon($ibnQueue):$bnQueueFlowmon($ibnQueue) bnQueue($ibnQueue):$bnQueue($ibnQueue)"
		}
		foreach flow [$bnQueueFlowmon($ibnQueue) flows] {
		    	#unmonitor the flow
			$bnQueue($ibnQueue) unmonitor-flow $flow 
		}	
	}
}

proc duplex-link { n1 n2 bw delay type args } {
	global ns pam
	
	eval $ns duplex-link $n1 $n2 $bw $delay $type $args
	
	if { [string match *IIA* $type ] } then {
		set n12Link [$ns link [$n1 id] [$n2 id]]
		set n21Link [$ns link [$n2 id] [$n1 id]]
		set n12Queue [$n12Link queue]
		set n21Queue [$n21Link queue]
		
		$n12Queue set iia_from_addr_ [$n1 node-addr]
		$n12Queue set iia_to_addr_ [$n2 node-addr]
		$n21Queue set iia_from_addr_ [$n2 node-addr]
		$n21Queue set iia_to_addr_ [$n1 node-addr]
	}
}

proc simplex-link { n1 n2 bw delay type args } {
	global ns pam
	
	eval $ns simplex-link $n1 $n2 $bw $delay $type $args
	
	if { [string match *IIA* $type ] } then {
		set n12Link [$ns link [$n1 id] [$n2 id]]
		set n12Queue [$n12Link queue]
		
		$n12Queue set iia_from_addr_ [$n1 node-addr]
		$n12Queue set iia_to_addr_ [$n2 node-addr]
	}	
}

proc getQueue {srcAddr dstAddr} {
	global ns pam 
	
	set srcNode [$ns get-node-by-addr $srcAddr]
	set dstNode [$ns get-node-by-addr $dstAddr]
	
	set theLink [$ns link $srcNode $dstNode]
	set theQueue [$theLink queue]
	
	if {$pam(ns_db)>=2} {
		set nsnow [$ns now];
		puts "nsnow:$nsnow getQueue $srcAddr>$dstAddr theQueue:$theQueue";
	}
	
	return $theQueue
}

#linkGqmd the direction to generate link. 1: i->j AQM j->i DropTail; 2: i->j AQM j->i AQM;
proc genRtrNodeLink {rtrGi rtrGj linkGbw linkGdl linkGqms linkGqs linkGqmd} {
	global ns pam bnlNnow nRtr bnLink bnQueue bnQueueFlowmon queueTF

	if {![info exists nRtr($rtrGi)]} {
		if { $pam(ur_app) == 3 } {set nRtr($rtrGi) [$ns DelayBox]} else {set nRtr($rtrGi) [$ns node]}
	}
	if {![info exists nRtr($rtrGj)]} {
		if { $pam(ur_app) == 3 } {set nRtr($rtrGj) [$ns DelayBox]} else {set nRtr($rtrGj) [$ns node]}
	}
	
	if { [string match *IIA* $linkGqms ] } then {
		set linkGqms "$linkGqms/Innate"
	}
	
	set nAddri [$nRtr($rtrGi) node-addr]
	set nAddrj [$nRtr($rtrGj) node-addr]
	set linkType ""

	if {$linkGqmd==2} {
		duplex-link $nRtr($rtrGi) $nRtr($rtrGj) [expr $linkGbw]Mb [expr $linkGdl]ms $linkGqms
		set linkType "duplex-link"
	} elseif {$linkGqmd==1} {
		simplex-link $nRtr($rtrGi) $nRtr($rtrGj) [expr $linkGbw]Mb [expr $linkGdl]ms $linkGqms
		simplex-link $nRtr($rtrGj) $nRtr($rtrGi) [expr $linkGbw]Mb [expr $linkGdl]ms DropTail
		set linkType "simplex-link"
	}
	$ns queue-limit $nRtr($rtrGi) $nRtr($rtrGj) $linkGqs
	$ns queue-limit $nRtr($rtrGj) $nRtr($rtrGi) $linkGqs
	set bnli1 $bnlNnow
	set bnli2 [expr $bnlNnow+1]
	set bnlNnow [expr $bnlNnow+2]
	set bnLink($bnli1) [$ns link $nRtr($rtrGi) $nRtr($rtrGj)]
	set bnLink($bnli2) [$ns link $nRtr($rtrGj) $nRtr($rtrGi)]
	if {$linkGqms=="RED/PD"} {
		set bnQueue($bnli1) [$bnLink($bnli1) queue]
		set bnQueueFlowmon($bnli1) [$bnQueue($bnli1) makeflowmon $bnLink($bnli1)]
		if {$linkGqmd==2} {
			set bnQueue($bnli2) [$bnLink($bnli2) queue]
			set bnQueueFlowmon($bnli2) [$bnQueue($bnli2) makeflowmon $bnLink($bnli2)]
		}
	}
	#Set Queue Trace
	if { $pam(ns_of) >= 1 } {
		$ns trace-queue $nRtr($rtrGi) $nRtr($rtrGj) $queueTF	
		$ns trace-queue $nRtr($rtrGj) $nRtr($rtrGi) $queueTF
	}
	
	if {$pam(ns_db)>=2} {
		set nsnow [$ns now];
		puts "nsnow:$nsnow $linkType nRtr($rtrGi)@$nAddri nRtr($rtrGj)@$nAddrj [expr $linkGbw]Mb [expr $linkGdl]ms $linkGqms $linkGqs";
	}
}

proc genSrvNodeLink {srvGinSrv linkGbw linkGdl linkGqms} {
	global ns pam nRtr nSrv queueTF
	
	if {![info exists nSrv($srvGinSrv)]} {
		set nSrv($srvGinSrv) [$ns node]
		set nAddrSrv [$nSrv($srvGinSrv) node-addr]
		set nAddrRtr [$nRtr($srvGinSrv) node-addr]
		$nSrv($srvGinSrv) shape hexagon
		if { [string match *IIA* $linkGqms ] } then {
			set linkGqms "$linkGqms/Adaptive"
		}
		if {$pam(ns_db)>=2} {
			set nsnow [$ns now];		
			puts "nsnow:$nsnow duplex-link nSrv($srvGinSrv)@$nAddrSrv nRtr($srvGinSrv)@$nAddrRtr [expr $linkGbw]Mb [expr $linkGdl]ms $linkGqms";
		}
		duplex-link $nSrv($srvGinSrv) $nRtr($srvGinSrv) [expr $linkGbw]Mb [expr $linkGdl]ms $linkGqms
		if { [string match *IIA* $linkGqms ] } then {
			set queue [getQueue $nAddrRtr $nAddrSrv]
			$ns at $pam(tm_fi) "$queue print-flow-statistics";
		}
		#Set Queue Trace
		if { $pam(ns_of) >= 1 } {
			$ns trace-queue $nSrv($srvGinSrv) $nRtr($srvGinSrv) $queueTF	
			$ns trace-queue $nRtr($srvGinSrv) $nSrv($srvGinSrv) $queueTF
		}
	}
}

proc genUsrNodeLink {usrGinRtr usrGinSrv linkGbw linkGdl linkGqms usrGn usrGapp} {
	global ns pam usrNnow nRtr nUsr agUsr apUsr tcpTF nSrv agSrvUsr src_delay loss_rate src_bw PM

	for {set i 0} {$i < $usrGn} {incr i} { 
		#Create Topo
		set ui $usrNnow
		set nUsr($ui) [$ns node]
		set nAddr [$nUsr($ui) node-addr]
		set usrNnow [expr $usrNnow+1]
		
		#!!! need random
		duplex-link $nUsr($ui) $nRtr($usrGinRtr) [expr $linkGbw]Mb [expr $linkGdl]ms $linkGqms
	
		if {$usrGapp == 1 || $usrGapp==0} {
			#Attach Agent
			set agUsr($ui) [new Agent/TCP/Newreno] 
			$ns attach-agent $nUsr($ui) $agUsr($ui) 
			if { $usrGapp==0} {
				set apUsr($ui) [new Application/FTP] 
			}
			if { $usrGapp==1} {
				set apUsr($ui) [new Application/Telnet] 
			}
			$apUsr($ui) attach-agent $agUsr($ui) 
			set agSrvUsr($ui) [new Agent/TCPSink] 
			$ns attach-agent $nSrv($usrGinSrv) $agSrvUsr($ui) 
			$ns connect $agUsr($ui) $agSrvUsr($ui)
			$agUsr($ui) set fid_ 1 
			
			#Tcp Trace
			if { $pam(ns_of) >=2 } {
				$agUsr($ui) attach $tcpTF
				$agUsr($ui) trace cwnd_
				$agUsr($ui) trace rtt_ 
				$agUsr($ui) trace srtt_ 
				$agUsr($ui) trace rttvar_
			}
		
			#Set Application Paramter
			$agUsr($ui) set packetSize_ $pam(ur_ps)
			#$agUsrSend($i) set minrto_ 1
		
			#Schedule !!! need random 
			set dit 0;
			if {$pam(ur_rs) == 1} {
				set dit [integer [expr $pam(ur_sp)-$pam(ur_st)]];
			}
			if {$pam(ns_db)>=2} {
				set nsnow [$ns now];
				set ap_st [expr $pam(ur_st)+$dit];				
				puts "nsnow:$nsnow apUsr($ui)@$nAddr $ap_st - $pam(ur_sp)";
			}
			$ns at [expr $pam(ur_st)+$dit] "$apUsr($ui) start"
			$ns at $pam(ur_sp) "$apUsr($ui) stop"
		}
	
		if {$usrGapp == 2 || $usrGapp == 3} {
			# HTTP
			if { $usrGapp == 3 } {
				# setup rules for DelayBoxes
				foreach inRtr [array names nRtr] {
					$nRtr($inRtr) add-rule [$nUsr($ui) id] [$nSrv($usrGinSrv) id] $src_delay $loss_rate $src_bw
				}
			}
			# set server and client	
			$PM set-server $nSrv($usrGinSrv)
			$PM set-client $nUsr($ui)
		}	
	}
}

proc genAtkNodeLink {atkGinRtr atkGinSrv linkGbw linkGdl linkGqms atkGn atkGng atkGtg atkGtp} {
	global ns pam atkNnow nRtr nAtk agAtk apAtk nSrv agSrvAtk lastAtkSendState

	if {$atkGn > 0 && $atkGng > 0 && $pam(ak_pr) > 0 && $pam(ak_ps) > 0 && $pam(ak_bp) > 0 && $pam(ak_ap) > 0} {
		set ak_ngm [expr $atkGn/$atkGng];#number of member per group
		#set ak_dtg [expr $pam(ak_ap)/$pam(ak_ng)/1000.0];
		set ak_dtg [expr $atkGtg/1000.0];#the start time difference between each group
		for {set i 0} {$i < $atkGn} {incr i} { 
			#Create Topo
			set ai $atkNnow
			set nAtk($ai) [$ns node]
			set nAddr [$nAtk($ai) node-addr]
			set atkNnow [expr $atkNnow+1]

			#!!! need modify
			duplex-link $nAtk($ai) $nRtr($atkGinRtr) [expr $linkGbw]Mb [expr $linkGdl]ms $linkGqms
		
			#Set Nam
			$nAtk($ai) color red
			$nAtk($ai) shape square
			
			#Attach Agent
			set agAtk($ai) [new Agent/UDP]
			$ns attach-agent $nAtk($ai) $agAtk($ai) 
			set apAtk($ai) [new Application/Traffic/CBR]
			$apAtk($ai) attach-agent $agAtk($ai) 
		
			set agSrvAtk($ai) [new Agent/Null] 
			$ns attach-agent $nSrv($atkGinSrv) $agSrvAtk($ai)
			$ns connect $agAtk($ai) $agSrvAtk($ai)
			$agAtk($ai) set fid_ 2 
		
			if {$pam(ak_spf_lv) > 0} {	
				#Spoof config , this code need agent-leo.h/cc and necessary modification in udp.h/cc and tcp.h/cc
				$agAtk($ai) set saddr_min_ $pam(ak_spf_mn)
				$agAtk($ai) set saddr_max_ $pam(ak_spf_mx)
				$agAtk($ai) set spoof_level_ $pam(ak_spf_lv)
				#$agAtkSend($i) print-leoinfo
			}
			
			#Set Application Paramter	
			$apAtk($ai) set packet_size_ $pam(ak_ps)
			
			#Attack Schedule			
			#Flooding DDoS attacks
			if {$atkGtp == 0} {
				$apAtk($ai) set rate_ $pam(ak_pr)Mb
				set dt 0;
				if {$pam(ak_rs) == 1} {
					set rndint [integer [expr ($pam(ak_sp)-$pam(ak_st))*1000]];
					set dt [expr $rndint/1000.0];
				}
				$ns at [expr $pam(ak_st)+$dt] "$apAtk($ai) start";
				$ns at $pam(ak_sp) "$apAtk($ai) stop";
				if {$pam(ns_db)>=2} {
					set nsnow [$ns now];					
					puts "nsnow:$nsnow apAtk($ai)@$nAddr [expr $pam(ak_st)+$dt] - $pam(ak_sp)";
				}
			}
			
			#Low-rate DDoS attacks
			if {$atkGtp == 1} {
				$apAtk($ai) set rate_ $pam(ak_pr)Mb
				#Loop for period attack
				set ak_ig [bottomDivide $i $ak_ngm];
				for {set it [expr $pam(ak_st)+$ak_ig*$ak_dtg]} {$it < $pam(ak_sp)} {set it [expr $it+$pam(ak_ap)/1000.0]} { 
					set dit 0;
					if {$pam(ak_rs) == 1} {
						set rndint [integer [expr $pam(ak_ap)-$pam(ak_bp)]];
						set dit [expr $rndint/1000.0];
					}
					$ns at [expr $it+$dit] "$apAtk($ai) start";
					$ns at [expr $it+$dit+$pam(ak_bp)/1000.0] "$apAtk($ai) stop";
					if {$pam(ns_db)>=2} {
						set nsnow [$ns now];
						puts "nsnow:$nsnow apAtk($ai)@$nAddr [expr $it+$dit] - [expr $it+$dit+$pam(ak_bp)/1000.0]";
					}					
				}
			}
			
			#Follow tcp cwnd DDoS attack		
			if {$atkGtp == 2} {
				$apAtk($ai) set rate_ $pam(ak_pr)Mb
				#$ns at $pam(ak_st) "$apAtk($ai) start"
				set lastAtkSendState($ai) 0
				#Loop for follow tcp cwnd attack
				for {set it $pam(ak_st)} {$it < $pam(ak_sp)} {set it [expr $it+$pam(ak_cp)/1000.0]} { 
					#setAtkSendState $i 0
					$ns at $it "setAtkSendState $ai $ai"
				}
				$ns at $pam(ak_sp) "$apAtk($ai) stop"
			}
		
		}
	}
}

proc genIIAAgent {srcAddr dstAddr} {
	global ns pam iiaAgent
	
	set srcNode [$ns get-node-by-addr $srcAddr]
	set dstNode [$ns get-node-by-addr $dstAddr]
		
	set srcNid [$srcNode id]
	set dstNid [$dstNode id]
	
	if { ![info exists iiaAgent($srcNid:$dstNid)] } {
		set iiaAgent($srcNid:$dstNid) [new Agent]
		set iiaAgent($dstNid:$srcNid) [new Agent]
		$ns attach-agent $srcNode $iiaAgent($srcNid:$dstNid)
		$ns attach-agent $dstNode $iiaAgent($dstNid:$srcNid) 
		$ns connect $iiaAgent($srcNid:$dstNid) $iiaAgent($dstNid:$srcNid)
	}
	
	$srcNode color gold
	$dstNode color gold
	
	if {$pam(ns_db)>=2} {
		set nsnow [$ns now];
		puts "nsnow:$nsnow genIIAAgent $srcAddr>$dstAddr iiaAgent:$iiaAgent($srcNid:$dstNid)";
	}
	
	return $iiaAgent($srcNid:$dstNid)
}

proc showIIAResponse {srcAddr dstAddr atkAddr} {
	global ns pam

	set srcNode [$ns get-node-by-addr $srcAddr]
	set dstNode [$ns get-node-by-addr $dstAddr]
		
	set srcNid [$srcNode id]
	set dstNid [$dstNode id]
	set atkNid [$ns get-node-id-by-addr $atkAddr]

	$srcNode label "block $atkNid>$srcNid at $dstNid"
	$srcNode label-color red
	
	if {$pam(ns_db)>=2} {
		set nsnow [$ns now];
		puts "nsnow:$nsnow showIIAResponse $atkNid>$srcNid at $dstNid";
	}
}

set genNetStep(rtr) "Generating Router nodes and bottle network topology"
set genNetStep(srv) "Generating Server nodes and links"
set genNetStep(usr) "Generating User nodes, links, and flows"
set genNetStep(atk) "Generating Attacker nodes, links, and flows"

#duplex-link $nSrv($srvGinSrv) $nRtr($srvGinSrv) $pam(nt_bw)Mb $pam(nt_dl)ms $linkGqms
proc genNetwork_dumbbell {} {
#mbn
#        nUsr                       
#            \                                  
#             nRtr(0)---nRtr(1)---nSrv(1)
#            /                        
#        nAtk

	global ns pam bn_qms genNetStep
	
	if {$pam(ns_db)>=1} {puts $genNetStep(rtr)}
	genRtrNodeLink 0 1 $pam(bn_bw) $pam(bn_dl) $bn_qms $pam(bn_qs) 2
	if {$pam(ns_db)>=1} {puts $genNetStep(srv)}
	genSrvNodeLink 1 $pam(nt_bw) $pam(nt_dl) "DropTail"
	if {$pam(ns_db)>=1} {puts $genNetStep(usr)}
	genUsrNodeLink 0 1 $pam(nt_bw) $pam(nt_dl) "DropTail" $pam(ur_n) $pam(ur_app)
	if {$pam(ns_db)>=1} {puts $genNetStep(atk)}
	genAtkNodeLink 0 1 $pam(nt_bw) $pam(nt_dl) "DropTail" $pam(ak_n) $pam(ak_ng) $pam(ak_tg) $pam(ak_tp)
}

proc genNetwork_tree2 {} {
#mbn
#        nUsr                nSrv(0)             nUsr
#          |                   |                   |
# nAtk---nRtr(3)---nRtr(1)---nRtr(0)---nRtr(2)---nRtr(5)---nAtk
#                    |                   |     
#           nUsr---nRtr(4)             nRtr(6)---nUsr
#                    |                   |
#                  nAtk                nAtk

	global ns pam bn_qms genNetStep
	
	if {$pam(ns_db)>=1} {puts $genNetStep(rtr)}
	genRtrNodeLink 0 1 $pam(bn_bw) $pam(bn_dl) $bn_qms $pam(bn_qs) 2
	genRtrNodeLink 0 2 $pam(bn_bw) $pam(bn_dl) $bn_qms $pam(bn_qs) 2	
	genRtrNodeLink 1 3 $pam(bn_bw) $pam(bn_dl) $bn_qms $pam(bn_qs) 2
	genRtrNodeLink 1 4 $pam(bn_bw) $pam(bn_dl) $bn_qms $pam(bn_qs) 2
	genRtrNodeLink 2 5 $pam(bn_bw) $pam(bn_dl) $bn_qms $pam(bn_qs) 2
	genRtrNodeLink 2 6 $pam(bn_bw) $pam(bn_dl) $bn_qms $pam(bn_qs) 2
	if {$pam(ns_db)>=1} {puts $genNetStep(srv)}
	genSrvNodeLink 0 $pam(nt_bw) $pam(nt_dl) "DropTail"
	if {$pam(ns_db)>=1} {puts $genNetStep(usr)}
	genUsrNodeLink 3 0 $pam(nt_bw) $pam(nt_dl) "DropTail" $pam(ur_n) $pam(ur_app)
	genUsrNodeLink 4 0 $pam(nt_bw) $pam(nt_dl) "DropTail" $pam(ur_n) $pam(ur_app)
	genUsrNodeLink 5 0 $pam(nt_bw) $pam(nt_dl) "DropTail" $pam(ur_n) $pam(ur_app)	
	genUsrNodeLink 6 0 $pam(nt_bw) $pam(nt_dl) "DropTail" $pam(ur_n) $pam(ur_app)
	if {$pam(ns_db)>=1} {puts $genNetStep(atk)}
	genAtkNodeLink 3 0 $pam(nt_bw) $pam(nt_dl) "DropTail" $pam(ak_n) $pam(ak_ng) $pam(ak_tg) $pam(ak_tp)	
	genAtkNodeLink 4 0 $pam(nt_bw) $pam(nt_dl) "DropTail" $pam(ak_n) $pam(ak_ng) $pam(ak_tg) $pam(ak_tp)
	genAtkNodeLink 5 0 $pam(nt_bw) $pam(nt_dl) "DropTail" $pam(ak_n) $pam(ak_ng) $pam(ak_tg) $pam(ak_tp)	
	genAtkNodeLink 6 0 $pam(nt_bw) $pam(nt_dl) "DropTail" $pam(ak_n) $pam(ak_ng) $pam(ak_tg) $pam(ak_tp)
}

proc genNetwork_tree2_2 {} {
#mbn
#        nUsr                nSrv(3)             nUsr
#          |                   |                   |
#        nRtr(0)---nRtr(1)---nRtr(3)---nRtr(5)---nRtr(4)
#                    |                   |     
#           nUsr---nRtr(2)             nRtr(6)---nUsr
#                    |                   |
#                  nAtk                nAtk

	global ns pam bn_qms genNetStep
	
	if {$pam(ns_db)>=1} {puts $genNetStep(rtr)}
	genRtrNodeLink 0 1 $pam(bn_bw) $pam(bn_dl) $bn_qms $pam(bn_qs) 2
	genRtrNodeLink 2 1 $pam(bn_bw) $pam(bn_dl) $bn_qms $pam(bn_qs) 2	
	genRtrNodeLink 1 3 $pam(bn_bw) $pam(bn_dl) $bn_qms $pam(bn_qs) 2
	genRtrNodeLink 4 5 $pam(bn_bw) $pam(bn_dl) $bn_qms $pam(bn_qs) 2
	genRtrNodeLink 6 5 $pam(bn_bw) $pam(bn_dl) $bn_qms $pam(bn_qs) 2
	genRtrNodeLink 5 3 $pam(bn_bw) $pam(bn_dl) $bn_qms $pam(bn_qs) 2
	if {$pam(ns_db)>=1} {puts $genNetStep(srv)}
	genSrvNodeLink 3 $pam(nt_bw) $pam(nt_dl) "DropTail"
	if {$pam(ns_db)>=1} {puts $genNetStep(usr)}
	genUsrNodeLink 0 3 $pam(nt_bw) $pam(nt_dl) "DropTail" $pam(ur_n) $pam(ur_app)	
	genUsrNodeLink 2 3 $pam(nt_bw) $pam(nt_dl) "DropTail" $pam(ur_n) $pam(ur_app)
	genUsrNodeLink 4 3 $pam(nt_bw) $pam(nt_dl) "DropTail" $pam(ur_n) $pam(ur_app)	
	genUsrNodeLink 6 3 $pam(nt_bw) $pam(nt_dl) "DropTail" $pam(ur_n) $pam(ur_app)
	if {$pam(ns_db)>=1} {puts $genNetStep(atk)}
	genAtkNodeLink 0 3 $pam(nt_bw) $pam(nt_dl) "DropTail" $pam(ak_n) $pam(ak_ng) $pam(ak_tg) $pam(ak_tp)	
	genAtkNodeLink 2 3 $pam(nt_bw) $pam(nt_dl) "DropTail" $pam(ak_n) $pam(ak_ng) $pam(ak_tg) $pam(ak_tp)
	genAtkNodeLink 4 3 $pam(nt_bw) $pam(nt_dl) "DropTail" $pam(ak_n) $pam(ak_ng) $pam(ak_tg) $pam(ak_tp)		
	genAtkNodeLink 6 3 $pam(nt_bw) $pam(nt_dl) "DropTail" $pam(ak_n) $pam(ak_ng) $pam(ak_tg) $pam(ak_tp)
}

proc genNetwork_line1 {} {
#mbn
#          
#        nRtr(7)---nRtr(5)---nRtr(3)---nRtr(1)---nRtr(0)---nSrv(0)
#          |         |         |         |     
#        nUsr      nRtr(6)   nRtr(4)   nRtr(2)
#                    |        /  \       |
#                  nAtk    nUsr nAtk   nUsr

	global ns pam bn_qms genNetStep
	
	if {$pam(ns_db)>=1} {puts $genNetStep(rtr)}
	;
	if {$pam(ns_db)>=1} {puts $genNetStep(srv)}
	;
	if {$pam(ns_db)>=1} {puts $genNetStep(usr)}
	;
	if {$pam(ns_db)>=1} {puts $genNetStep(atk)}
	;
}

proc genNetwork_Internet {type} {
#mbn
#           nUsr            nSrv
#             |               |    
#    nAtk---nRtr(2)         nRtr(4)
#              \             /
#              nRtr(0)---nRtr(1)
#              /             \
#           nRtr(3)         nRtr(5)---nAtk
#             |               |
#           nUsr            nUsr

	global ns pam bn_qms genNetStep
	
	if {$pam(ns_db)>=1} {puts $genNetStep(rtr)}
	genRtrNodeLink 0 1 [expr $pam(bn_bw)*2] $pam(bn_dl) $bn_qms $pam(bn_qs) 2
	genRtrNodeLink 0 2 [expr $pam(bn_bw)+1] $pam(bn_dl) $bn_qms $pam(bn_qs) 2
	genRtrNodeLink 0 3 [expr $pam(bn_bw)+1] $pam(bn_dl) $bn_qms $pam(bn_qs) 2
	genRtrNodeLink 1 4 [expr $pam(bn_bw)+1] $pam(bn_dl) $bn_qms $pam(bn_qs) 2
	genRtrNodeLink 1 5 [expr $pam(bn_bw)+1] $pam(bn_dl) $bn_qms $pam(bn_qs) 2
	if {$pam(ns_db)>=1} {puts $genNetStep(srv)}
	genSrvNodeLink 4 [expr $pam(nt_bw)*2] $pam(nt_dl) $bn_qms
	if {$pam(ns_db)>=1} {puts $genNetStep(usr)}
	genUsrNodeLink 2 4 $pam(nt_bw) $pam(nt_dl) "DropTail" $pam(ur_n) $pam(ur_app)
	genUsrNodeLink 3 4 $pam(nt_bw) $pam(nt_dl) "DropTail" $pam(ur_n) $pam(ur_app)
	genUsrNodeLink 5 4 $pam(nt_bw) $pam(nt_dl) "DropTail" $pam(ur_n) $pam(ur_app)
	if {$pam(ns_db)>=1} {puts $genNetStep(atk)}
	switch $type {
		0 {}
		1 {genAtkNodeLink 2 4 $pam(nt_bw) $pam(nt_dl) "DropTail" $pam(ak_n) $pam(ak_ng) $pam(ak_tg) $pam(ak_tp)}
		2 {genAtkNodeLink 5 4 $pam(nt_bw) $pam(nt_dl) "DropTail" $pam(ak_n) $pam(ak_ng) $pam(ak_tg) $pam(ak_tp)}
		3 {genAtkNodeLink 2 4 $pam(nt_bw) $pam(nt_dl) "DropTail" $pam(ak_n) $pam(ak_ng) $pam(ak_tg) $pam(ak_tp)
		   genAtkNodeLink 5 4 $pam(nt_bw) $pam(nt_dl) "DropTail" $pam(ak_n) $pam(ak_ng) $pam(ak_tg) $pam(ak_tp)}
		default {}
	}
}


proc finish {} {
	global ns allTF namTF tcpTF queueTF 
	$ns flush-trace
	close $allTF
	close $namTF
	close $tcpTF
	close $queueTF
	exit 0 
}

set ns [new Simulator]

#usage
puts "leodos2.tcl"
getPam $argc $argv
printPam

Queue/RED set bytes_ false ;		# default changed on 10/11/2004.
Queue/RED set queue_in_bytes_ false ;	# default changed on 10/11/2004.
#Queue/RED set adaptive_ 0 ;

Queue/RED/Robust set hash_bins_ 23
Queue/RED/Robust set hash_levels_ 2
Queue/RED/Robust set score_max_ 10
Queue/RED/Robust set score_min_ -1
Queue/RED/Robust set score_pass_ 0
Queue/RED/Robust set last_drop_time_ 0ms
Queue/RED/Robust set drop_related_period_ 10ms

#Queue/SFB/Robust set setbit false ;#ECN support turned on by default
#Queue/SFB/Robust set pm_benign_th_ 0#0
#Queue/SFB/Robust set benign_flow_queue_size_ 50#50
#Queue/SFB/Robust set last_pkt_time_ 0ms
#Queue/SFB/Robust set pkt_related_period_ 0ms

#Queue/RED/PP set hash_bins_ 100
#Queue/RED/PP set hash_levels_ 2
#Queue/RED/PP set interval_priority_ 2000ms
#Queue/RED/PP set interval_after_last_drop_time_ 1000ms
#Queue/RED/PP set last_drop_time_ 0ms

Agent/TCP set minrto_ 1;

#Queue/Blue set setbit false ;#ECN support turned on by default
#Queue/SFB set setbit false ;#ECN support turned on by default

#Added by leoking IIA config 0
Queue/DropTail/IIA set iia_from_addr_ -1
Queue/DropTail/IIA set iia_to_addr_ -1
Queue/DropTail/IIA set iia_fid_ 5
Queue/DropTail/IIA set max_flows_ 100

Queue/DropTail/IIA/Innate set abnormal_related_period_ 20ms

Queue/DropTail/IIA/Adaptive set abnormal_pkt_ratio_threshold_ 0.5
Queue/DropTail/IIA/Adaptive set abnormal_pkt_number_threshold_ 200
Queue/DropTail/IIA/Adaptive set mip_sending_interval_ 1000ms
Queue/DropTail/IIA/Adaptive set max_agents_ 100
#Added by leoking IIA config 1

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
set queueTF [open ./result/leodos_queue.tr w]


#Set Nam
$ns color 1 blue
$ns color 2 red
$ns color 5 green

#For PackMimeHttp traffic
if {$pam(ur_app) == 2 || $pam(ur_app) == 3 } {
	remove-all-packet-headers
	add-packet-header IP TCP
	$ns use-scheduler Heap

	set PM [new PackMimeHTTP]

	if { $pam(ur_app) == 3 } {
		#Trace set show_tcphdr_ 1 
		   
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

#1 For DropTail; 2 For RED; 3 For RED-PD; 4 For Blue; 5 For SFB
set bn_qms "DropTail";
switch $pam(bn_qm) {
	1 {set bn_qms "DropTail";}
	2 {set bn_qms "RED";}
	3 {set bn_qms "RED/PD";}
	4 {set bn_qms "Blue";}
	5 {set bn_qms "SFB";}
	6 {set bn_qms "CBQ";}
	7 {set bn_qms "FQ";}
	8 {set bn_qms "SFQ";}
	9 {set bn_qms "DRR";}
	10 {set bn_qms "PI";}
	11 {set bn_qms "Vq";}
	12 {set bn_qms "REM";}
	13 {set bn_qms "GK";}
	14 {set bn_qms "SRR";}
	15 {set bn_qms "RED/Robust";}
	16 {set bn_qms "SFB/Robust";}
	17 {set bn_qms "RED/PP";}
	18 {set bn_qms "DropTail/IIA";}
	default {set bn_qms "DropTail";}
}
puts "bn_qms\t$bn_qms";

#generate network
switch $pam(bn_tp) {
	1 {set bn_tps "dumbbell";genNetwork_dumbbell;}
	2 {set bn_tps "tree2";genNetwork_tree2;}
	3 {set bn_tps "tree2_2";genNetwork_tree2_2;}
	10 {set bn_tps "Internet_0";genNetwork_Internet 0;}
	11 {set bn_tps "Internet_1";genNetwork_Internet 1;}
	12 {set bn_tps "Internet_2";genNetwork_Internet 2;}
	13 {set bn_tps "Internet_3";genNetwork_Internet 3;}
	default {set bn_tps "dumbbell";genNetwork_dumbbell;}
}
puts "bn_tps\t$bn_tps";

#redpd
if {$bn_qms=="RED/PD"} {
	if {$pam(ns_db)>=1} {puts "Setting redpd"}
	if {$pam(ns_db)>=2} {
		set bnQueueSize [array size bnQueue]
		set bnQueueFlowmonSize [array size bnQueueFlowmon]linkGqmd
		puts "initial bnQueueFlowmonSize:$bnQueueFlowmonSize bnQueueSize:$bnQueueSize"
	}
	set monitorTime [expr $pam(ur_st)+0.01]
	$ns at $monitorTime "monitorFlow 0.1"
	set monitorTime [expr $pam(ak_st)+0.01]
	$ns at $monitorTime "monitorFlow 0.1"
	#$ns at $pam(ur_sp)-20 "unmonitorFlow"
}

#PackMime Settings
if {$pam(ns_db)>=1} {puts "PackMime Settings"}
if {$pam(ur_app) == 2 || $pam(ur_app) == 3} {
	$PM set-outfile "./result/leodos_http.tr"
	$PM set-rate $pam(ur_cr)
	$PM set-1.1
	$PM set-TCP Newreno

        $ns at $pam(ur_st) "$PM start"
        $ns at $pam(ur_sp) "$PM stop"
}

$ns at $pam(tm_fi) "finish"
puts "usrNnow\t$usrNnow"
puts "atkNnow\t$atkNnow"
puts "bnlNnow\t$bnlNnow"
if {$pam(ns_db)>=1} {puts "start to run"}
$ns run
