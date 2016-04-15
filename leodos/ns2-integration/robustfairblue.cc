/* -*-	Mode:C++; c-basic-offset:8; tab-width:8; indent-tabs-mode:t -*- */
/*
 * Copyright (c) 1994 Regents of the University of California.
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
 * 3. Al ladvertising materials mentioning features or use of this software
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
 */

/*Ported to ns2.1b8 by Sunil Thulasidasan, LANL. 11/05/2001*/
/*Last updated on 09/13/2002 */

/*
* This file is a part of the implementation of the Resilient Stochastic Fair Blue (RSFB) algorithm that was proposed by Changwang Zhang et al. in [1].
*
* References:
* 1. Changwang Zhang, Jianping Yin, and Zhiping Cai, RSFB: a Resilient Stochastic Fair Blue algorithm against spoofing DDoS attacks, in International Symposium on Communication and Information Technology (ISCIT), 2009.
*/

#include <math.h>
#include <stdlib.h>
#include <sys/types.h>
#include "robustfairblue.h"
#include "random.h"
#include "delay.h"
#include "flags.h"

FlowQueue::FlowQueue(int msize) {
	size=0;
	head=NULL;
	tail=NULL;
	maxsize=msize;
}

FlowQueue::~FlowQueue() {
	FlowQueueItem * qfqiptr=head;
	FlowQueueItem * qfqiptr_prior=NULL;
	while(qfqiptr!=NULL){
		qfqiptr_prior=qfqiptr;
		qfqiptr=qfqiptr->next;
		delete qfqiptr_prior;
	}
}

int FlowQueue::enque(FlowQueueItem fqi) {
	FlowQueueItem *newfqiptr=new FlowQueueItem();
	*newfqiptr=fqi;
	
	if(maxsize>0) {
		int qindex=find(fqi);		
		
		if(tail==NULL) {
			tail=newfqiptr;
		} else {
			tail->next=newfqiptr;
			tail=newfqiptr;
		}
	
		if(head==NULL) {
			head=newfqiptr;
		}	

		size++;	
	
		if(qindex>=0) {
			deque(qindex);
		}
	
		if(size>maxsize) {
			deque(0);
		}
		#ifdef DEBUG_FLOWQUEUE
		double now=Scheduler::instance().clock();
		printf("%lf FlowQueue enque qindex=%d fqi.flowId=%u .lastPktTime=%lf \n", now, qindex, fqi.flowId, fqi.lastPktTime);
		#endif
	}
	
	return size;
}

FlowQueueItem FlowQueue::deque(int index) {
	FlowQueueItem fqi;
	FlowQueueItem * qfqiptr=NULL;
	if(index==0 && size>0) {
		qfqiptr=head;
		head=head->next;
		size--;
		fqi=*qfqiptr;
		delete qfqiptr;	
	} else if(index<size) {
		FlowQueueItem * qfqiptr_prior=head;
		int i=0;
		while(i<index-1) {
			qfqiptr_prior=qfqiptr_prior->next;
			i++;
		}
		qfqiptr=qfqiptr_prior->next;
		qfqiptr_prior->next=qfqiptr->next;
		size--;
		fqi=*qfqiptr;
		delete qfqiptr;					
	}

	#ifdef DEBUG_FLOWQUEUE
	double now=Scheduler::instance().clock();
	printf("%lf FlowQueue deque index=%d fqi.flowId=%u .lastPktTime=%lf \n", now, index, fqi.flowId, fqi.lastPktTime);
	#endif

	return fqi;
}

int FlowQueue::find(FlowQueueItem fqi) {
	int index=-1;
	if(size>0) {
		int i=0;
		FlowQueueItem * qfqiptr=head;
		for(i=0;i<size;i++) {
			if(fqi.flowId==qfqiptr->flowId) {
				index=i;
				break;
			}
			qfqiptr=qfqiptr->next;
		}
	}
	return index;	
}

static class RobustFairBlueClass : public TclClass {

 public:
	RobustFairBlueClass() : TclClass("Queue/SFB/Robust") {}
	TclObject* create(int, const char*const*) {
		return (new RobustFairBlue());
	}
} class_robustfairblue;


RobustFairBlue::RobustFairBlue() : FairBlue() {
	pkt_accepted_=TRUE;
//	benign_flows_i=0;
	bind("pm_benign_th_", &pm_benign_th_);
	bind("benign_flow_queue_size_", &benign_flow_queue_size_);
/*
	last_bin_index_=0;
	bind_time("last_pkt_time_", &last_pkt_time_);
	bind_time("last_drop_time_", &last_drop_time_);
	bind_time("pkt_related_period_", &pkt_related_period_);
*/
}

/*
int RobustFairBlue::sfbhash(hdr_ip* pkt, int level, unsigned int fudge) {
	double now = Scheduler::instance().clock();
	unsigned int bini=0;
	switch (level) {
	case 2:
		if (now-last_drop_time_<pkt_related_period_) {
			bini=last_bin_index_;
		} else {
			bini=FairBlue::sfbhash(pkt, level, fudge);
			last_bin_index_=bini;
		}	
		break;
	default:
		bini=FairBlue::sfbhash(pkt, level, fudge);
		break;
	}
	last_pkt_time_=now;
	return(bini);
}
*/

unsigned int RobustFairBlue::hashPkt(Packet* pkt) {
	hdr_ip* iph=hdr_ip::access(pkt);

	unsigned int a=int(iph->saddr());
/*	
	unsigned int b=int(iph->sport());
	unsigned int c=int(iph->daddr());
	unsigned int d=int(iph->dport());
	
	unsigned int h=((a << 6) + (b << 12) + (c << 18) + (d << 24));
*/
	unsigned int h=a;
	return h;
}


int RobustFairBlue::inBenignFlow(Packet* pkt) {
	int rtn=0;

	FlowQueueItem fqi;
	fqi.flowId=hashPkt(pkt);

	if(flowQueue.find(fqi)>=0) {
		rtn=1;
	}

/*
	unsigned int h=hashPkt(pkt);

	int i=0;
	for (i=0;i<benign_flow_queue_size_;i++) {
		if (h==benign_flows[i]) {
			rtn=1;
			break;
		}
	}	#ifdef DEBUG_RSFB
		double now=Scheduler::instance().clock();
		hdr_ip* iph=hdr_ip::access(pkt);
		int saddr=int(iph->saddr());
		int daddr=int(iph->daddr());
		int flowid=int(iph->flowid());
		printf("%lf flowid:%d SrcAddress:%d DstAddress:%d addBenignFlow flowQueueSize:%d\n", now, flowid, saddr, daddr, flowQueueSize);
	#endif
*/

	return rtn;	
}

int RobustFairBlue::addBenignFlow(Packet* pkt) {
	flowQueue.maxsize=benign_flow_queue_size_;
	
	FlowQueueItem fqi;
	fqi.flowId=hashPkt(pkt);
	fqi.lastPktTime=Scheduler::instance().clock();

	int flowQueueSize=flowQueue.enque(fqi);
/*
	if (!inBenignFlow(pkt)) {
		benign_flows[benign_flows_i]=hashPkt(pkt);
		benign_flows_i++;
		if (benign_flows_i>=benign_flow_queue_size_) {
			benign_flows_i=0;
		}
	}
*/	
	#ifdef DEBUG_RSFB
	double now=Scheduler::instance().clock();
	hdr_ip* iph=hdr_ip::access(pkt);
	int saddr=int(iph->saddr());
	int daddr=int(iph->daddr());
	int flowid=int(iph->flowid());
	printf("%lf id:%d %d->%d addBenignFlow flowQueueSize:%d\n", now, flowid, saddr, daddr, flowQueueSize);
	#endif

	return flowQueueSize;
}

void RobustFairBlue::enque(Packet* pkt) {
	pkt_accepted_=TRUE;
	FairBlue::enque(pkt);
	if (pkt_accepted_) { // This means pkt is not droped
		for (int i=0; i < SFQ_LEVELS; i++) {
			if (bins[i][p_bins[i]][cursfq_].pmark <= pm_benign_th_) {
				addBenignFlow(pkt);
			}
		}
	}	
	return;
}

void RobustFairBlue::drop(Packet* pkt) {
	#ifdef DEBUG_RSFB
	double now = Scheduler::instance().clock();
	hdr_ip* iph=hdr_ip::access(pkt);
	printf("%lf SFB drop id:%d %d->%d \n", now, iph->flowid(), iph->saddr(), iph->daddr());
	#endif

	pkt_accepted_=FALSE;
	if(inBenignFlow(pkt)) {
		
		//if(q_->length()+1 < qlim_/2) {
		if(q_->length()+1 < qlim_) {
			q_->enque(pkt);
			#ifdef DEBUG_RSFB
			printf("RRED benign enqued because q_->length()+1 < qlim_ \n");
			#endif
		} else if(!refineQueue(pkt)) {	
			#ifdef DEBUG_RSFB
			printf("RRED refineQueue Failed droped \n");
			#endif	
			FairBlue::drop(pkt);		
		}
	} else {
		#ifdef DEBUG_RSFB
		printf("RRED not benign droped \n");
		#endif	
		FairBlue::drop(pkt);
	}

	return;
}

int RobustFairBlue::refineQueue(Packet* pkt) {
	int rtn=0;

	for (Packet *p=q_->head(); p; p=p->next_) {	
		if(!inBenignFlow(p)) {

			#ifdef DEBUG_RSFB
			double now=Scheduler::instance().clock();
			hdr_ip* iph_in=hdr_ip::access(pkt);
			hdr_ip* iph_out=hdr_ip::access(p);
			printf("%lf refineQueue Out id:%d %d->%d In id:%d %d->%d\n", now, iph_out->flowid(), iph_out->saddr(), iph_out->daddr(), iph_in->flowid(), iph_in->saddr(), iph_in->daddr());
			#endif

			#ifdef DEBUG_RSFB
			printf("QueueLength 1:%d ",q_->length());
			#endif
			q_->remove(p);
			#ifdef DEBUG_RSFB
			printf("QueueLength 2:%d ",q_->length());
			#endif
			q_->enque(pkt);
			#ifdef DEBUG_RSFB
			printf("QueueLength 3:%d \n",q_->length());
			#endif
			FairBlue::drop(p);
			rtn=1;
			break;
		}
	}

	return rtn;
}
