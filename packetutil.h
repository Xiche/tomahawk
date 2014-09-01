/*
 *
 * packetutil.h
 *
 * Copyright (c) 2003 TippingPoint Technologies. All rights reserved.
 * Please see LICENSE for licensing information
 *
 */

#ifndef _PACKETUTIL_
#define _PACKETUTIL_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <time.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <netinet/in.h> 
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include "eventloop.h"
#include "pcap.h"
#include "alloc.h"

/*
 * Flags for each packet in a handler
 */
#define SENT	1
#define RECV	2

#define AVERAGE_PACKET_SIZE 400
#define ARP 0x608
#define IP  0x008

/* These defines are used when rewriting IP addresses
 * in the file.
 *
 * HASH(ip) - Function that maps an IP address to an index in the RecvIP
 *	table.  No two IP addresses should map to the same index.  Currently,
 *	the function just bit-shifts 16 to the right, meaning only the last two
 *	bytes of an IP address are used (since it's stored in network order).
 *
 * RESERVED_LOWER_BYTES - some of the addresses that look like broadcast addresses
 *	are skipped unless the file IP is a broadcast address (e.g., X.X.X.255 or
 *	X.X.X.0, see isBroadcast() function for details).  Therefore not all 65536 
 *	can be used.  RESERVED_LOWER_BYTES is the number that are skipped.  It is
 *	used to determine if the number of unique IP addresses in a trace is too
 *	high (see LoadTrace function for details).
 *		-all 256 of X.X.0.n and X.X.255.n (i.e., 2*256)
 *		-2 each of X.X.{1-254}.0 and X.X.{1-254}.255 (i.e., 2*254)
 *
 * MAX_UNIQUE_IPS - number of allowed unique IP addresses in a pcap before the
 *	mapping algorithm will not be able to guarantee generation of one-to-one
 *	mapping
 */
#define HASH(ip)	((ip)>>16)
#define RESERVED_LOWER_BYTES (2*256 + 2*254)
#define MAX_UNIQUE_IPS ( (1<<16) - RESERVED_LOWER_BYTES )

#define MARK(p)		p->refCount++
#define FREE(p)		if (--p->refCount == 0) {free(p);}

#define NOT_BCAST	0x0
#define BCAST_0		0x1
#define BCAST_255	0x2

#define MAX_ACTIVE_HANDLERS 250		/* The maximum number of active handlers.  Must be < 254 */
#define MAX_PACKETS_OUTSTANDING 50	/* The maximum number of packets that can be unaccounted 
					 * for at one time (per handler) */
#define MAX_TRACE_LOOKAHEAD 500		/* The maximum number of packets that will be reviewed in the
					 * pcap when attempting to assemble a pcaket group to send */

#define STOPPED   0
#define RUNNING   1

/*
 * IFACE_I and IFACE_J are used to track which interface a packet will be sent out.
 */

#define IFACE_I    1
#define IFACE_J    0
#define NOT_ACTIVE -1

typedef unsigned char Mac[6];

/*
 * The following structure is used in translating IP addresses
 *   TraceIP -- maintains a list of unique IPs in a trace and 
 *		the lowest 2 bytes of their corresponding mapped IP.  One per trace
 * TraceIP is an variable length array.
 */

typedef struct TraceIP {
    in_addr_t addr;
    unsigned short mapIp; /* Lower 16-bits of the IP address this address maps to */
    int iface;      /* Interface this address is connected to (i.e., IFACE_I or IFACE_J) */
} TraceIP;

/*
 * The following stores the data associated with one packet
 */
typedef struct Packet {
    unsigned int sec;		/* Packet timestamp */
    int usec;		        /* Packet timestamp */
    char iface;			/* Interface out which the packet should be sent */
    unsigned char *buffer;	/* The packet data */
    unsigned short len;         /* Data length */
    in_addr_t saddr;            /* Source address (in file) */
    in_addr_t daddr;            /* Dest address (in file) */
    unsigned short wireSrc;	/* Lower 16-bits of source address (on wire) */
    unsigned short wireDst;	/* Lower 16-bits of dest address (on wire) */
    unsigned short ipHash;	/* Hash of Protocol, srcIP, and dstIP.  */
} Packet;

typedef struct Trace {
    char filename[256];
    char name[16];
    Packet *pkt;
    unsigned int numPkts;
    int maxPkts;
    int size;
    TraceIP *traceIP;
    int numIPs;
    int maxIPs;
    int numActive;
    int maxActive;
    int numComplete;
    int maxComplete;
    int timeout;
    int retrans;
    int modAddrs;
    unsigned int retransCount;
    unsigned int completed;
    unsigned int timedOut;
    unsigned int warningCount;	/* Flag used to throttle the number of warnings that get printed */
    IdleCB *createHandlerCb;
    TimerCB *timedCreateHandlerCb;
    struct Trace *next;
} Trace;

typedef struct flowStateInfo {
    char iface;	   /* The interface out which packets should be sent for this flow hash ( IFACE_I or IFACE_J ) 
		             OR NOT_ACTIVE -> no packets for this flow are outstanding */
    char otherHostSeen;	   /* Flag indicating whether a packet for this flow that needs to go out a 
			    * different interface has already been inspected for this send group.
			    */
    unsigned char numPkts; /* Number of pkts in the group for this flow */
} flowStateInfo;

typedef struct Handler {
    Trace *trace;
    unsigned char *flags;
    int refCount;          /* Number of pointers to this object */
    unsigned char runState;	/* run state for this handler */
    unsigned char progressMade; /* Flag indicating whether any progress has been made since the last
				 * time the hander was reviewed by the checkTimeouts function */
    unsigned int lowestUnsentPktId;  /* lowest ID of a packet that has not been sent */
    unsigned short numPktsSent; /* Number of packets the handler sent in a pktsOut group */
    unsigned short numPktsRecv; /* Number of packets the handler has received in a pktsOut group */
    unsigned int numTracePktsRecv; /* Total number of packets the handler has received */
    unsigned int pktsOut[MAX_PACKETS_OUTSTANDING];   /* Array containing the IDs for  
				* packets that the handler has sent but not yet received */
    unsigned short numFlowsInGroup; /* Number of flows the handler sent in a packet group */
    unsigned short flowsOut[MAX_PACKETS_OUTSTANDING];   /* Array containing the flow hashes for  
				* flows that the handler has sent but not yet received */
    flowStateInfo flowsOutStateTable[65535];
    int retrans;           /* Number of retransmissions left before timeout */
    unsigned long long int sendTime; /* Time last packet was sent */
    int numIPs;
    unsigned short id;
    TimerCB *timeoutCb;
    struct Handler *next;
} Handler;

/* extern Handler *handlerList; */
extern Trace *traceList;

unsigned char IsBroadcast(in_addr_t inetAddr);
unsigned short RewriteBroadcastSuffix(unsigned short ipToRewrite, in_addr_t origAddr);
unsigned short IncrAddr(unsigned short x1, int n);
unsigned int SubAddr(unsigned int x1, unsigned int x2);
void CompressHandlers(void);
void DeleteHandler(in_addr_t wireIP);
void AddHandler(in_addr_t wireIP, Handler *h);
Handler *GetHandler(const u_char *packetData, int len, int modAddrs, unsigned char startId, unsigned char endId);
unsigned short GetRandomLowerIP(void);
void AddTraceIP(Trace *trace, in_addr_t addr, int iface, unsigned short mapIp);
int ParseEtherAddr(char *ether, Mac dst);
void PrintBinary(unsigned int n);
void PrintTime(void *data);
void PrintPacket(int n, int recv, const u_char *buffer);
void PrintTrace(Trace *trace);
void PrintHandlerSendGroup(Handler *h);
void PrintFlowsOutStateTable(Handler *h);
int PacketEqual(Packet *p, const u_char *data, int caplen, int actualLen);
in_addr_t GetWireIP(unsigned short handlerId, unsigned short wireIPSuffix, in_addr_t addr, unsigned char startAddrByte);
unsigned short NewChecksum(unsigned short check, unsigned int old, unsigned int new);
unsigned int CRC32(unsigned char *message, int msgLength);
unsigned short HashIpData (u_int8_t protocol, unsigned short sip, unsigned short dip);

/* prototypes for activeHandlers functions */
void InitializeActiveHandlers(unsigned char startId, unsigned char endId);
unsigned short GetHandlerId(unsigned char loopStart, unsigned char loopEnd, Handler *h);
void FreeHandlerId(unsigned short id);

void InitializeInterfaceFlowStatus(Handler *h);

#endif
