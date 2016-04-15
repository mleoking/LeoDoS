 /* -*-	Mode:C++; c-basic-offset:8; tab-width:8; indent-tabs-mode:t -*- */
/*
 * Copyright (c) 1990-1997 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the Computer Systems
 *	Engineering Group at Lawrence Berkeley Laboratory.
 * 4. Neither the name of the University nor of the Laboratory may be used
 *    to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *
 * Here is one set of parameters from one of Sally's simulations
 * (this is from tcpsim, the older simulator):
 * 
 * ed [ q_weight=0.002 thresh=5 linterm=30 maxthresh=15
 *         mean_pktsize=500 dropmech=random-drop queue-size=60
 *         plot-file=none bytes=false doubleq=false dqthresh=50 
 *	   wait=true ]
 * 
 * 1/"linterm" is the max probability of dropping a packet. 
 * There are different options that make the code
 * more messy that it would otherwise be.  For example,
 * "doubleq" and "dqthresh" are for a queue that gives priority to
 *   small (control) packets, 
 * "bytes" indicates whether the queue should be measured in bytes 
 *   or in packets, 
 * "dropmech" indicates whether the drop function should be random-drop 
 *   or drop-tail when/if the queue overflows, and 
 *   the commented-out Holt-Winters method for computing the average queue 
 *   size can be ignored.
 * "wait" indicates whether the gateway should wait between dropping
 *   packets.
 */
 
/*
* This file is a part of the implementation of the Robust Random Early Detection (RRED) algorithm that was proposed by Changwang Zhang et al. in [1].
* 
* References:
* 1. Changwang Zhang, Jianping Yin, Zhiping Cai, and Weifeng Chen, RRED: Robust RED Algorithm to Counter Low-rate Denial-of-Service Attacks, IEEE Communications Letters, vol. 14, pp. 489-491, 2010.
*/

#ifndef lint
static const char rcsid[] =
     "@(#) $Header: /cvsroot/nsnam/ns-2/queue/red-robust.cc,v 1.88 2007/10/23 06:55:54 seashadow Exp $ (LBL)";
#endif

#include <math.h>
#include <sys/types.h>
#include "config.h"
#include "template.h"
#include "random.h"
#include "flags.h"
#include "delay.h"
#include "red-robust.h"

static class RobustREDClass : public TclClass {
public:
	RobustREDClass() : TclClass("Queue/RED/Robust") {}
	TclObject* create(int argc, const char*const* argv) {
		//printf("creating RED Queue. argc = %d\n", argc);
		
		//mod to enable RED to take arguments
		if (argc==5) 
			return (new RobustREDQueue(argv[4]));
		else
			return (new RobustREDQueue("Drop"));
	}
} class_robustred;

RobustREDQueue::RobustREDQueue(const char * trace) : REDQueue(trace) {
	bind("hash_bins_", &hash_bins_);
	bind("hash_levels_", &hash_levels_);
	bind("score_max_", &score_max_);
	bind("score_min_", &score_min_);
	bind("score_pass_", &score_pass_);
	bind_time("last_drop_time_", &last_drop_time_);
	bind_time("drop_related_period_", &drop_related_period_);
	resetBins(0);
}
	

void RobustREDQueue::enque(Packet* pkt) {

	if (dropAnomaly(pkt)) {
		//reportDrop(pkt); //Where report? need to further thinking
		updateBinsDroptime(pkt);
		drop(pkt);		

	} else {
		REDQueue::enque(pkt);
	}
	
	return;
}

void RobustREDQueue::reportDrop(Packet* pkt) {
	double drop_time=updateBinsDroptime(pkt);
	last_drop_time_=drop_time;

	return;
}

int RobustREDQueue::hashPkt(Packet* pkt, int ilevel) {
	int ibin=0;

	hdr_ip* iph=hdr_ip::access(pkt);

	unsigned int param1=(int)(iph->saddr());
	unsigned int param2=(int)(iph->daddr());
	//unsigned int param3=int(iph->sport());
	//unsigned int param4=int(iph->dport());


	ibin=((param1<<ilevel)+param2)%hash_bins_;

	return ibin;
}

void RobustREDQueue::resetBins(int v) {
	int i,j;
	for (i=0;i<hash_levels_;i++) {
		for (j=0;j<hash_bins_;j++) {
			bins_[i][j].score=v;
			bins_[i][j].last_drop_time=0;
		}
	}
}

void RobustREDQueue::printBins() {
	double now=Scheduler::instance().clock();
	int i,j;
	printf("%lf hash_levels_=%d hash_bins_=%d last_drop_time_=%lf\n", now, hash_levels_, hash_bins_, last_drop_time_);
	for (i=0;i<hash_levels_;i++) {
		for (j=0;j<hash_bins_;j++) {
			printf("[%d,%lf]\t", bins_[i][j].score, bins_[i][j].last_drop_time);	
		}
		printf("\n");
	}
}

double RobustREDQueue::updateBinsDroptime(Packet *pkt) {
	double now=Scheduler::instance().clock();

	int ilevel=0;
	int ibin=0;
	for (ilevel=0;ilevel<hash_levels_;ilevel++){
		ibin=hashPkt(pkt, ilevel);
		bins_[ilevel][ibin].last_drop_time=now;
	}

	return now;
}

int RobustREDQueue::dropAnomaly(Packet *pkt) {
	int rtn=1;
	double now=Scheduler::instance().clock();

	#ifdef RREDDEBUG
	hdr_ip* iph=hdr_ip::access(pkt);
	printf("%lf saddr=%d daddr=%d ", now, iph->saddr(), iph->daddr());
	#endif

	int ilevel=0;
	int ibin=0;
	for (ilevel=0;ilevel<hash_levels_;ilevel++){
		ibin=hashPkt(pkt, ilevel);

		#ifdef RREDDEBUG
		printf("ibin%d=%d ", ilevel, ibin);
		#endif

		// Need further analysis
		if (now-MAX(last_drop_time_, bins_[ilevel][ibin].last_drop_time)<drop_related_period_) {
		//if (now-bins_[ilevel][ibin].last_drop_time<drop_related_period_) {
		//if (now-last_drop_time_<drop_related_period_) {
			if (bins_[ilevel][ibin].score>score_min_){
				bins_[ilevel][ibin].score=bins_[ilevel][ibin].score-1;
			}			
		} else {
			if (bins_[ilevel][ibin].score<score_max_){
				bins_[ilevel][ibin].score=bins_[ilevel][ibin].score+1;
			}
		}
		if (bins_[ilevel][ibin].score>=score_pass_) {
			rtn=0;
		}

		#ifdef RREDDEBUG
		printf("[%d,%lf] ", bins_[ilevel][ibin].score, bins_[ilevel][ibin].last_drop_time);
		#endif
	}		
	
	#ifdef RREDDEBUG
	printf("\n");
	if (rtn==1) {
		printf("Anomaly Detected !!\n");
	}
	printBins();	
	#endif

	return rtn;
}
