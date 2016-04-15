
#ifndef ns_agent_leo_h
#define ns_agent_leo_h

#include "random.h"
#include "ip.h"

//You have to write the class in Java style, say write function details in the class defination.
//This is to avoid the repeat definition error when using the traditional c++ style like "AgentLeo::initpkt_after{xxx}"

#define agent_class_public_begin() \
	int saddr_min_;\
	int saddr_max_;\
	int spoof_level_;\
	void agent_initpkt_end(Packet* p) const {\
		int rndNumber=0;\
		hdr_ip* iph = hdr_ip::access(p);\
		\
		switch(spoof_level_) {\
		case 0:\
			break;\
		case 1:\
			rndNumber = Random::integer(saddr_max_-saddr_min_)+saddr_min_;\
			iph->saddr() = rndNumber;\
			break;\
		default:\
			break;\
		}\
	}

#define agent_construction_end() {\
	bind("saddr_min_", &saddr_min_);\
	bind("saddr_max_",&saddr_max_);\
	bind("spoof_level_",&spoof_level_);\
	saddr_min_=1;\
	saddr_max_=100;\
	spoof_level_=0;\
}

#endif

