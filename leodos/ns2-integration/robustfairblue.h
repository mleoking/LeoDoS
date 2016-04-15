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
 */

/*Ported to ns2.1b8 by  Sunil Thulasidasan, LANL; 11/05/2001 */
/*Updated on 09/011/2002*/

/*
* This file is a part of the implementation of the Resilient Stochastic Fair Blue (RSFB) algorithm that was proposed by Changwang Zhang et al. in [1].
*
* References:
* 1. Changwang Zhang, Jianping Yin, and Zhiping Cai, RSFB: a Resilient Stochastic Fair Blue algorithm against spoofing DDoS attacks, in International Symposium on Communication and Information Technology (ISCIT), 2009.
*/

#ifndef ns_robustfairblue_h
#define ns_robustfairblue_h

#include "fairblue.h"

#define BENIGN_FLOW_BIN_N 100
#define BENIGN_FLOW_BIN_L 2

#define BENIGN_FLOW_N 100

//#define DEBUG_RSFB 1
//#define DEBUG_FLOWQUEUE 1

class FlowQueueItem {
  public:
	FlowQueueItem() { flowId=-1; lastPktTime=-1; next=NULL; };
	FlowQueueItem operator=(FlowQueueItem newfqi) {flowId=newfqi.flowId; lastPktTime=newfqi.lastPktTime; next=newfqi.next; return *this; };
	unsigned int flowId;
	double lastPktTime;
	FlowQueueItem *next;
};

class FlowQueue {
  public:
	FlowQueue(int msize=0);
	~FlowQueue();
	int enque(FlowQueueItem fqi);
	FlowQueueItem deque(int index=0);
	int find(FlowQueueItem fqi);
	int size;
	int maxsize;
  protected:
	FlowQueueItem *head;
	FlowQueueItem *tail;
};

class RobustFairBlue : public FairBlue {
  public:
	RobustFairBlue(); 
	//~RobustFairBlue(); 
  protected:
	//int hashit(unsigned int a, unsigned int b, unsigned int c, unsigned int d, int modulus);
	//void enque(Packet* p) { if ((q_->length() + 1) <= qlim_) {q_->enque(p); } };//This is for test use	
	//int sfbhash(hdr_ip* pkt, int level, unsigned int fudge);
	void enque(Packet* pkt);
	void drop(Packet* pkt);
	unsigned int hashPkt(Packet* pkt);
	int addBenignFlow(Packet* pkt);
	int inBenignFlow(Packet* pkt);
	int refineQueue(Packet* pkt);
/*
	int benign_flow_bins_[BENIGN_FLOW_BIN_L][BENIGN_FLOW_BIN_N];

	unsigned int benign_flows[BENIGN_FLOW_N];
	int benign_flows_i;
*/

	FlowQueue flowQueue;

	bool pkt_accepted_;
	
	double pm_benign_th_;
	int benign_flow_queue_size_;
/*	int last_bin_index_;
	double last_pkt_time_;
	double last_drop_time_;
	double pkt_related_period_;	
*/
};

#endif






