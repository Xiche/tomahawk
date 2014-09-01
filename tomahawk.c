/*
 * tomahawk.c
 *
 * Copyright (c) 2002, 2003, 2004 TippingPoint Technologies.
 * All rights reserved.
 *
 * Please see LICENSE for licensing information
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netpacket/packet.h>
#include <arpa/inet.h>

#include "eventloop.h"
#include "packetutil.h"
#include "alloc.h"
#include "pcap.h"
#include "pcap-int.h"

#ifdef min
#undef min
#endif
#ifdef max
#undef max
#endif
#define max(x,y)	((x)>(y)?(x):(y))
#define min(x,y)	((x)<(y)?(x):(y))

/*
 * The following controls the maximum number of outstanding
 * packets on an interface.
 */
#ifdef DEBUG_STACK
#define ENTER(str)	DebugEnter(str)
#define EXIT(str)	DebugExit(str)
#define DEBUG(str)	DebugPush(str)
#else
#define ENTER(str)
#define EXIT(str)
#define DEBUG(str)
#endif

typedef struct Interface
{
    int numOutstanding;         /* Number of packets expected to be
                                 * available on the interface */
    int progress;               /* Iteration variable to track any
                                 * changes to numOutstanding */
    int fd;                     /* Socket */
    char device[32];            /* Device name (e.g., "eth1") */
    FileCB *cb;                 /* File callback */
    Mac eaddr;                  /* Ethernet address of interface */
    struct sockaddr_ll sa;      /* Socket address -- attaches socket to
                                 * device */
} Interface;

typedef struct FileInfo
{
    char *name;
    int maxActive;
    int modAddrs;
    int timeout;                /* per packet timeout */
    int retrans;                /* number of retrans before timeout */
    int loop;                   /* number of loops */
} FileInfo;

/*
 * The following data structure is used for "Faked" receives.
 */
typedef struct RecvRecord
{
    Handler *h;
    unsigned int packetNum;
} RecvRecord;

/* Used to bitmask IP header to detect framentation */
#define IP_MF		0x2000      /* More fragment bit */
#define IP_OFFSET	0x1FFF      /* Fragment offset part */

static int maxOutstanding = 15;
static int maxPcapLookAhead = MAX_TRACE_LOOKAHEAD;
static unsigned long numSent;
static unsigned long numRecv;
static int numActive;
static int maxActive = MAX_ACTIVE_HANDLERS;
static int maxHandlers;
static int playMode = 0;
static int modAddrs = 1;
static int warnMode = 0;
static int logMode = 0;
static FILE *logFile = NULL;
static int isBadPcap = 0;
static double desiredRate = 0;
static long long int bytesSent = 0;
static double startTime;
static double rateCheckTime;
/* startHandlerId and endHandlerId are the start and 
 * end values used for handler Ids. */
static unsigned char startHandlerId = 1;
static unsigned char endHandlerId = MAX_ACTIVE_HANDLERS;
/*
 * maxHandlerIdInUse tracks the maximum handler ID
 * currently in use by tomahawk.  Used to when deciding
 * what the ID for a newly created handler should be
 */
static unsigned char maxHandlerIdInUse = 0;

static char *startAddr = NULL;
static unsigned char firstByte = 0;
static FileInfo fileInfo[65536];
static Interface if1, if2;
static Handler *handlerList = NULL;
static TimerCB *timeoutCB = NULL;
int debugFlag;
static int randomizeIPs;
static int quiet;
static char *blockStr;
static int blockStrNum;
static int blockStrMax;

#define NUM_COMMANDS (6)

static CmdHandler *cmdCb[NUM_COMMANDS];
void Usage(char *cmd);
void GetEther(char *device, Mac eaddr);
int WriteInterface(Interface * interface, unsigned char *payload, int len);
void OpenInterface(char *device, Interface * rv);
void CloseInterface(Interface * interface);
void CreateHandler(void *data);
void FinishHandler(Handler * h, int timeout);
void FinishTrace(Trace * t);
void LoadPacket(u_char * user, const struct pcap_pkthdr *pcap_hdr, const u_char * data);
Trace *LoadTrace(char *name, int loop, int maxActive, int timeout, int retrans, int modAddrs);
void RecvPacket(u_char * data, const struct pcap_pkthdr *pcap_hdr, const u_char * packetData);
void ReadPacket(void *data);
void SendPackets(void *data);
void ResendPackets(Handler * h);
void CheckTimeouts(void *data);
void NewConnection(Peer * p, void *userData);
void LogPacketInfo(Packet * pkt, char *msg);
unsigned char CanRewriteIP(struct iphdr *iph);

#ifdef DEBUG_STACK
static char debugStack[128];
static int debugDepth = 0;

/*
 *----------------------------------------------------------------------
 *
 * FUNCTION DebugEnter/DebugExit/DebugPush --
 *
 *	Routines to maintain the debug stack.
 *
 * Returns:
 *	Never returns (exits)
 *
 *----------------------------------------------------------------------
 */
void DebugPush(char *str)
{
    int i, len;
    char pad[64];
    char *end;

    assert(debugDepth < sizeof(pad));
    for (i = 0; i < debugDepth; i++)
    {
        pad[i] = ' ';
    }
    pad[i] = 0;
    len = strlen(str);
    end = debugStack + sizeof(debugStack) - len - debugDepth - 1;
    memmove(debugStack, debugStack + len + debugDepth + 1, sizeof(debugStack) - len);
    memcpy(end++, "\n", 1);
    memcpy(end, pad, debugDepth);
    end += debugDepth;
    memcpy(end, str, len);
    printf("%s%s\n", pad, str);
}

void DebugEnter(char *str)
{
    debugDepth++;
    DebugPush(str);
}

void DebugExit(char *str)
{
    debugDepth--;
}
#endif

/*
 *----------------------------------------------------------------------
 *
 * FUNCTION Usage --
 *
 *	Print a usage statement and exit
 *
 * Returns:
 *	Never returns (exits)
 *
 *----------------------------------------------------------------------
 */

void Usage(char *cmd)
{
    fprintf(stderr, "Usage: %s options\n", cmd);
    fprintf(stderr, "Options affecting all streams:\n");
    fprintf(stderr, "    -h              Print help and exit\n");
    fprintf(stderr, "    -Z              Debug mode (multiple -Z's increase)\n");
    fprintf(stderr, "    -W              Warning mode (enables extra checks and prints out warnings)\n");
    fprintf(stderr, "    -q              Quiet mode\n");
    fprintf(stderr, "    -R rate         playback rate in Mbps (default:" " unlimited\n");
    fprintf(stderr, "    -m sendGroupSize Maximum number of packets to gather "
            "before sending the group (default: %d)\n", maxOutstanding);
    fprintf(stderr, "    -w lookahead    Maximum number of packets to examime "
            "while gathering the group to send (default: %d)\n", maxPcapLookAhead);
    fprintf(stderr, "    -i interface1   Interface to send packets on\n");
    fprintf(stderr, "    -j interface2   Interface to send packets on\n");
    fprintf(stderr, "    -a startIpAddr  First IP address for mapped IPs\n");
    fprintf(stderr, "    -N maxActive    Max simultaneously active handlers\n");
    fprintf(stderr, "    -s startId      Lowest hadler ID to use (default: 1)\n");
    fprintf(stderr, "    -e endId        Highest handler ID to use (default: %d)\n",
            (MAX_ACTIVE_HANDLERS + 1));
    fprintf(stderr,
            "    -L logFile      Run in logMode and log packets that time out to logFile (- is STDOUT).\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Options individual streams (handlers):\n");
    fprintf(stderr, "    -A (0|1)        Modify IP addresses (default: true)\n");
    fprintf(stderr,
            "    -d              Randomize lower 2 bytes of IP address (use only when the pcap has 2 IPs in it.)\n");
    fprintf(stderr, "    -t timeout      Timeout for one packet(ms)\n");
    fprintf(stderr, "    -r retrans      Number of retransmission\n");
    fprintf(stderr, "    -n maxActive    Max number of handlers for a file\n");
    fprintf(stderr, "    -l loops        Number of times to replay file\n");
    fprintf(stderr, "    -f file         Pcap file to play\n");
    exit(1);
}

/*
 *----------------------------------------------------------------------
 *
 * FUNCTION HandleSegv --
 *
 *	This function is call on a seg fault
 *
 * Returns:
 *	Never returns (exits)
 *
 *----------------------------------------------------------------------
 */

static void HandleSegv(int i)
{
#ifdef DEBUG_STACK
    printf("Seg fault\ndebug stack:\n%s\n", debugStack);
#else
    printf("Seg fault\n");
#endif
    exit(-1);
}

/*
 *----------------------------------------------------------------------
 *
 * FUNCTION HandleInterrupt --
 *
 *	This function is call on ctrl-C
 *
 * Returns:
 *	Never returns (exits)
 *
 *----------------------------------------------------------------------
 */

static void CleanUp()
{
    int i;

    for (i = 0; i < NUM_COMMANDS; i++)
    {
        DeleteCmdHandler(cmdCb[i]);
    }
    CloseInterface(&if1);
    CloseInterface(&if2);
    while (traceList)
    {
        FinishTrace(traceList);
    }
    if (timeoutCB)
    {
        DeleteTimerCallback(timeoutCB);
    }
    if (blockStr)
    {
        free(blockStr);
    }
    DumpActiveMemory("mem.out");

    /*
     * Close the log file handle if we opened one.
     */
    if (logFile != (FILE *) NULL)
    {
        fclose(logFile);
    }

    /*
     * I haven't got this part working yet...
     * printf ("Latency stats (min/avg/max): %1.1f/%1.1f/%1.1f microseconds\n",
     *      1.0*minLat/clicksPerUSec, 1.0*sumLat/numLat/clicksPerUSec,
     *      1.0*maxLat/clicksPerUSec);
     */

#ifdef DEBUG_STACK
    printf("debug stack:\n%s\n", debugStack);
#endif
    exit(0);
}

static void HandleInterrupt(int i)
{
    CleanUp();
}

/*
 *----------------------------------------------------------------------
 *
 * FUNCTION GetEther --
 *
 *	This function is called to return the ethernet address (in
 *      ASCII format) associated with an interface.
 *
 * Returns:
 *	None
 *
 *----------------------------------------------------------------------
 */

void GetEther(char *device, Mac eaddr)
{
    char tmpName[256];
    char buf[256];
    FILE *file;
    int status;

    strcpy(tmpName, "/tmp/tmp_ether.name");
    sprintf(buf, "ifconfig %s | head -1 | awk '{print $5}' > %s", device, tmpName);
    status = system(buf);
    if (status != 0)
    {
        fprintf(stderr, "error opening executing %s\n", buf);
        unlink(tmpName);
        exit(1);
    }
    file = fopen(tmpName, "r");
    if (file == NULL)
    {
        fprintf(stderr, "error opening temp file %s\n", tmpName);
        unlink(tmpName);
        exit(1);
    }
    if (fgets(buf, 18, file) == NULL)
    {
        fprintf(stderr, "error reading from temp file %s\n", tmpName);
        fclose(file);
        unlink(tmpName);
        exit(1);
    }
    fclose(file);
    unlink(tmpName);

    if (ParseEtherAddr(buf, eaddr) == 0)
    {
        fprintf(stderr, "Error parsing ethernet address %s\n", buf);
        exit(1);
    }
}

/*
 *----------------------------------------------------------------------
 *
 * FUNCTION OpenInterface --
 *
 *	Open a raw interface and associate the RecvPacket callback
 *
 * Returns:
 *	None
 *
 *----------------------------------------------------------------------
 */

void OpenInterface(char *device, Interface * rv)
{
    int fd;
    struct ifreq ifr;

    fd = socket(PF_PACKET, SOCK_RAW, IPPROTO_RAW);
    rv->fd = fd;
    if (fd == 0)
    {
        fprintf(stderr, "Error opening %s: %s\n", device, strerror(errno));
        exit(1);
    }

    /*
     * Get device number
     */
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));

#ifdef DEBUG_RECV
    printf("Device %s, fd %d\n", device, rv->fd);
    fflush(stdout);
#endif

    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0)
    {
        fprintf(stderr, "Error getting index for device %s: %s\n", device, strerror(errno));
        exit(1);
    }

    /*
     * Compute the address struct
     */
    memset(&rv->sa, 0, sizeof(rv->sa));
    rv->sa.sll_family = AF_PACKET;
    rv->sa.sll_ifindex = ifr.ifr_ifindex;
    rv->sa.sll_protocol = htons(ETH_P_ALL);

    /*
     * Bind the socket to the device
     */
    if (bind(fd, (struct sockaddr *) &rv->sa, sizeof(rv->sa)) == -1)
    {
        fprintf(stderr, "Error binding socket to device %s: %s\n", device, strerror(errno));
        exit(1);
    }

    rv->cb = CreateFileCallback(rv->fd, ReadPacket, rv, NULL);

    if (playMode == 0)
    {
        GetEther(device, rv->eaddr);
    }
    strncpy(rv->device, device, sizeof(rv->device));
}

/*
 *----------------------------------------------------------------------
 *
 * FUNCTION WriteInterface --
 *
 *	Write a packet to a raw interface
 *
 * Returns:
 *	Number of bytes written, or -1 on error (w/errno set).
 *        ENOBUFS and EAGAIN are non-fatal errors.
 *
 *----------------------------------------------------------------------
 */

inline int WriteInterface(Interface * interface, unsigned char *payload, int len)
{

    numSent++;
    return sendto(interface->fd, payload, len, 0, (struct sockaddr *) NULL, 0);
}

/*
 *----------------------------------------------------------------------
 *
 * FUNCTION CloseInterface --
 *
 *	Close a raw interface;
 *
 * Returns:
 *	None
 *
 *----------------------------------------------------------------------
 */

void CloseInterface(Interface * interface)
{
    close(interface->fd);
    DeleteFileCallback(interface->cb);
    interface->cb = NULL;
}

/*
 *----------------------------------------------------------------------
 *
 * FUNCTION CreatePacketSendGroup --
 *
 *	Gathers a group of packets from the trace that can be sent without
 *	waiting to receive others.  The collection algrithm keeps track of 
 *	flows so that a packet that is in response to a previous packet will
 *	not be added to the group.
 *
 * Returns:
 *	None
 *
 *----------------------------------------------------------------------
 */
void CreatePacketSendGroup(Handler * h)
{
    /* For convenience, define some pointers to Handler structure members */
    Trace *t = h->trace;
    Packet *p = t->pkt;

    /* Initialize the counters for this group */
    h->numPktsSent = 0;
    h->numPktsRecv = 0;
    unsigned int nextPktId = h->lowestUnsentPktId;
    unsigned char lowestIdUpdated = 0;

    /*
     * So we do not spend cycles looping to the end of the trace, set a stop value 
     */
    unsigned int stopPktId = nextPktId + maxPcapLookAhead;

    /*
     * Keep track of the total number of flows and the number of flows for which 
     * collection has been stopped due to a packet from the other side being enountered
     */
    h->numFlowsInGroup = 0;
    unsigned int numFlowsFilledOut = 0;

    /* 
     * Now collect the group.  We can add the packet while the following conditions are true:
     *  1- We have not reached the end of the trace
     *  2- We have not exceeded the selected maxActive window size
     *  3- The packet in question does not belong to the same conversation for which there is
     *      already an outstanding packet and the interface value is different.
     */
    while (nextPktId != t->numPkts)
    {
        if (h->numPktsSent >= maxOutstanding || nextPktId > stopPktId)
        {
            break;
        }

        /*
         * Skip those packets we've already sent
         */
        if (h->flags[nextPktId] & SENT)
        {
            nextPktId++;
            continue;
        }

        unsigned char addPacket = 0;

        /*
         * Examine the next packet and see if we can add it to the group that will be sent
         * If there are no packets already from this flow, the packet can be added
         */
        if (h->flowsOutStateTable[p[nextPktId].ipHash].numPkts == 0)
        {
            addPacket = 1;
            h->flowsOut[h->numFlowsInGroup] = p[nextPktId].ipHash;
            h->numFlowsInGroup++;
        }
        else
        {
            if (h->flowsOutStateTable[p[nextPktId].ipHash].iface == p[nextPktId].iface)
            {
                /*
                 * If the interface for the packets is the same, we can add it if we have not seen 
                 * a packet from the other host in the flow.
                 */
                if (h->flowsOutStateTable[p[nextPktId].ipHash].otherHostSeen == 0)
                {
                    addPacket = 1;
                }
            }
            else
            {
                /*
                 * If the interface for the packets is not the same, then update the otherHostSeen
                 * for the flow.
                 */
                if (!h->flowsOutStateTable[p[nextPktId].ipHash].otherHostSeen)
                {
                    h->flowsOutStateTable[p[nextPktId].ipHash].otherHostSeen = 1;
                    numFlowsFilledOut++;
                }
            }
        }

        if (addPacket)
        {
            h->pktsOut[h->numPktsSent] = nextPktId;
            h->flowsOutStateTable[p[nextPktId].ipHash].iface = p[nextPktId].iface;
            h->flowsOutStateTable[p[nextPktId].ipHash].numPkts++;
            h->numPktsSent++;
        }
        else
        {
            /*
             * Packet cannot be added to this send group.  Save the id of the
             * lowest unsent packet so it can be used to begin assembling the next group
             */

            if (!lowestIdUpdated)
            {
                h->lowestUnsentPktId = nextPktId;
                lowestIdUpdated = 1;
            }
        }

        /* Go to the next packet in the trace */
        nextPktId++;
    }

    /*
     * Update the id of the lowest unsent packet if it has not been changed
     */
    if (!lowestIdUpdated)
        h->lowestUnsentPktId = nextPktId;

#ifdef DEBUG_SENDGROUP
    printf("%u flows in this group (%u are filled out)\n", h->numFlowsInGroup, numFlowsFilledOut);
#endif

    /*
     * If there are some flows that are not filled out, look a bit farther for each one
     */
    if (h->numFlowsInGroup != numFlowsFilledOut)
    {
        int i;
        unsigned int pktId;

        for (i = 0; i < h->numFlowsInGroup; i++)
        {
            /*
             * Break if we are going to exceed the defined array size
             */
            if (h->numPktsSent >= MAX_PACKETS_OUTSTANDING)
                break;

            /*
             * Skip flows where we've already seen the other host
             */
            if (h->flowsOutStateTable[h->flowsOut[i]].otherHostSeen)
                continue;

            /*
             * Look ahead in the trace to try to fill out this flow.  We are only looking
             * for packets with the same flow hash and same interface.
             * Reset the starting packet ID
             */
            pktId = nextPktId;

            while (pktId != t->numPkts && h->numPktsSent < MAX_PACKETS_OUTSTANDING)
            {
                if (pktId > (stopPktId + maxPcapLookAhead))
                {
                    break;
                }

                if (p[pktId].ipHash == h->flowsOut[i])
                {
                    /*
                     * We found a packet with the same flow hash.  If the interface is
                     * same, add it.  If not, update otherHostSeen and break.
                     */
                    if (h->flowsOutStateTable[p[pktId].ipHash].iface == p[pktId].iface)
                    {
                        h->pktsOut[h->numPktsSent] = pktId;
                        h->flowsOutStateTable[p[pktId].ipHash].numPkts++;
                        h->numPktsSent++;

                        /*
                         * If we added the lowest unsent packet, we need to update it
                         */
                        if (pktId == h->lowestUnsentPktId)
                        {
                            h->lowestUnsentPktId = pktId + 1;
                            nextPktId = pktId + 1;
                        }
                    }
                    else
                    {
                        h->flowsOutStateTable[p[pktId].ipHash].otherHostSeen = 1;
                        numFlowsFilledOut++;
                        break;
                    }

                }

                /*
                 * Go to the next packet in the trace
                 */
                pktId++;
            }
        }

    }

#ifdef DEBUG_SENDGROUP
    printf("After greedy grab: %u flows in this group (%u are filled out)\n", h->numFlowsInGroup,
           numFlowsFilledOut);

    PrintHandlerSendGroup(h);
    PrintFlowsOutStateTable(h);
    fflush(stdout);
#endif

    return;
}

/*
 *----------------------------------------------------------------------
 *
 * FUNCTION CreateHandler --
 *
 *	Create a handler for a trace
 *
 * Returns:
 *	None
 *
 *----------------------------------------------------------------------
 */

void CreateHandler(void *data)
{
    Trace *t = (Trace *) data;
    Handler *h;
    int i;

    t->createHandlerCb = NULL;
    t->timedCreateHandlerCb = NULL;

    /*
     * If we're up to the max number of handlers, don't create a
     * new one.  We'll get called again when one finishes up
     */
    if (t->numActive >= t->maxActive)
    {
        return;
    }
    if ((t->numActive + t->numComplete) >= t->maxComplete)
    {
        return;
    }
    if (numActive >= maxActive)
    {
        return;
    }

    ENTER("CreateHandler");
    /*
     * Create one or more handlers to track progress through
     * the trace.
     */
    h = (Handler *) calloc(sizeof(Handler), 1);
    h->trace = t;

    /*
     * Get an ID for this handler.
     * We want to pick an ID that is higher than the highest ID in use
     * unless we have reached the maximum.
     */
    if (maxHandlerIdInUse == 0)
    {
        h->id = GetHandlerId(1, endHandlerId, h);
    }
    else
    {
        h->id = GetHandlerId(maxHandlerIdInUse + 1, endHandlerId, h);
    }

    /*
     * If the id returned was zero, try to get one by starting from the
     * low end of the specified range
     */
    if (h->id == 0)
    {
        h->id = GetHandlerId(startHandlerId, endHandlerId, h);
    }

    /* If the ID is still zero, then there is an error */
    if (h->id == 0)
    {
        fprintf(stderr, "Unable to get handler ID.  This is a fatal error.\n");
        exit(1);
    }

    /* Update the maximum ID in use */
    if (h->id > maxHandlerIdInUse)
    {
        maxHandlerIdInUse = h->id;
    }

    if (maxHandlerIdInUse >= endHandlerId)
    {
        /* We cannot get a higher handler ID, so start over */
        maxHandlerIdInUse = startHandlerId - 1;
    }

    h->flags = (unsigned char *) calloc(t->numPkts, 1);
    h->numTracePktsRecv = 0;
    h->lowestUnsentPktId = 0;
    h->retrans = t->retrans;
    h->sendTime = 0;

    /*
     * Set the flag for progress made to avoid a case where the timeout checking
     * coincides with the creation of a new handler.  This results in continual
     * timeouts.
     */
    h->progressMade = 1;
    h->runState = RUNNING;
    h->numIPs = t->numIPs;
    h->timeoutCb = NULL;
    h->next = handlerList;
    handlerList = h;

    /*
     * Initialize the State Table that keeps track of flow status of sent packets
     * and call the function to create the send group
     */
    InitializeInterfaceFlowStatus(h);
    CreatePacketSendGroup(h);

    SendPackets(h);
    t->numActive++;
    numActive++;
    if ((t->numActive < t->maxActive) &&
        ((t->numActive + t->numComplete) < t->maxComplete) &&
        (t->createHandlerCb == NULL && t->timedCreateHandlerCb == NULL))
    {
        /*
         * We are allowed to create another Handler.  Wait a bit before
         * starting so packets are not blasted all at once when tomahawk
         * begins.
         */
        t->timedCreateHandlerCb = CreateTimerCallback(100, CreateHandler, t, NULL);
    }
    for (i = 0, h = handlerList; h != NULL; i++, h = h->next)
    {
    }
    if (i > maxHandlers)
    {
        maxHandlers = i;
    }
    EXIT("CreateHandler");
}

/*
 *----------------------------------------------------------------------
 *
 * FUNCTION AppendState --
 *
 *	Add a string to the tail of a string variable
 *
 * Returns:
 *	None
 *
 *----------------------------------------------------------------------
 */

void AppendState(char *str)
{
    int len;

    len = strlen(str);

    /*
     * If we need to alloc or realloc blockStr, do it in 4K chunks
     */
    if (len + blockStrNum >= blockStrMax)
    {
        blockStrMax = 4096 * (1 + ((len + blockStrNum) / 4096));
        if (blockStr)
        {
            blockStr = realloc(blockStr, blockStrMax);
        }
        else
        {
            blockStr = malloc(blockStrMax);
        }
        memset(blockStr + blockStrNum, 0, blockStrMax - blockStrNum);
    }
    sprintf(blockStr + blockStrNum, " %s", str);
    blockStrNum += len + 1;
}

/*
 *----------------------------------------------------------------------
 *
 * FUNCTION FinishTrace --
 *
 *	This function is called when all the loops for a trace have
 *      completed.
 *
 * Returns:
 *	None
 *
 *----------------------------------------------------------------------
 */

void FinishTrace(Trace * t)
{
    Trace *prev, *curr;
    int i;
    char str[4096];

    ENTER("FinishTrace");
    if (!quiet)
    {
        printf("\n");
        if (!warnMode)
        {
            printf("Finished %d loops of trace %s", t->numComplete, t->filename);
            printf(" Completed: %d, Timed out: %d\n", t->completed, t->timedOut);
            printf("Retrans: %d\n", t->retransCount);
            printf("Sent: %lu\n", numSent);
            printf("Recv: %lu\n", numRecv);
        }

        if (warnMode || debugFlag)
        {
            printf("%u of %u replayable frames generated a warning for trace:\n%s\n\n",
                   t->warningCount, t->numPkts, t->filename);
        }
    }

    sprintf(str, "%s %d %d", t->filename, t->completed, t->timedOut);
    AppendState(str);

    EventuallyFree(t->traceIP, NULL);
    for (i = 0; i < t->numPkts; i++)
    {
        EventuallyFree(t->pkt[i].buffer, NULL);
    }
    EventuallyFree(t->pkt, NULL);

    /*
     * Remove t from traceList
     */
    for (prev = NULL, curr = traceList; curr != NULL; curr = curr->next)
    {
        if (curr == t)
        {
            break;
        }
        prev = curr;
    }
    if (prev)
    {
        prev->next = t->next;
    }
    else
    {
        traceList = t->next;
    }
    // Release (t);
    EventuallyFree(t, NULL);

    /*
     * If there are any traces that don't have active handlers,
     * start one now
     */
    for (curr = traceList; curr != NULL; curr = curr->next)
    {
        if (curr->numActive == 0)
        {
            curr->createHandlerCb = CreateIdleCallback(CreateHandler, curr, NULL);
            break;
        }
    }
    EXIT("FinishTrace");
}

/*
 *----------------------------------------------------------------------
 *
 * FUNCTION FinishHandler --
 *
 *	Finish a handler for a trace
 *
 * Returns:
 * FUNCTION FinishHandler --
 *
 *	Finish a handler for a trace
 *
 * Returns:
 *	None
 *
 *----------------------------------------------------------------------
 */

void FinishHandler(Handler * h, int timeout)
{
    Trace *t;
    Handler *prev, *curr;

    ENTER("FinishHandler");
    t = h->trace;

    if (!quiet)
    {
        printf("\n");
        if (timeout)
        {
            printf("Timeout 1 loop of trace %s (hid: %u)\n", t->filename, h->id);
        }
        else
        {
            printf("Completed 1 loop of trace %s (hid: %u)\n", t->filename, h->id);
        }

    }

    t->numActive--;
    t->numComplete++;
    numActive--;

    /* Free up the ID for reuse */
    FreeHandlerId(h->id);

    if (h->timeoutCb)
    {
        DeleteTimerCallback(h->timeoutCb);
        h->timeoutCb = NULL;
    }

    /*
     * Remove h from handlerList
     */
    for (prev = NULL, curr = handlerList; curr != NULL; curr = curr->next)
    {
        if (curr == h)
        {
            break;
        }
        prev = curr;
    }
    if (prev)
    {
        prev->next = h->next;
    }
    else
    {
        handlerList = h->next;
    }
    EventuallyFree(h->flags, NULL);
    // Release (h->trace);
    // Release (h);
    EventuallyFree(h, NULL);

    if ((t->numActive < t->maxActive) &&
        ((t->numActive + t->numComplete) < t->maxComplete) &&
        (t->createHandlerCb == NULL && t->timedCreateHandlerCb == NULL))
    {

        /*
         * If we timed out, then wait 500 ms before calling CreateHandler
         */
        if (timeout)
        {
            t->timedCreateHandlerCb = CreateTimerCallback(500, CreateHandler, t, NULL);
        }
        else
        {
            t->createHandlerCb = CreateIdleCallback(CreateHandler, t, NULL);
        }

    }
    else if (t->numComplete == t->maxComplete)
    {
        FinishTrace(t);
    }
    EXIT("FinishHandler");
}

/*
 *----------------------------------------------------------------------
 *
 * FUNCTION LoadPacket --
 *
 *	Callback function to add a packet to a trace.  This function
 *      is typically called from pcap_dispatch()
 *
 * Returns:
 *	None.
 *
 * Side effects:
 *	Packet is added to the trace (first parameter).
 *
 *----------------------------------------------------------------------
 */

void LoadPacket(u_char * user,  /* (IN/OUT) packet trace */
                const struct pcap_pkthdr *pcap_hdr, const u_char * data)
{
    Trace *trace = (Trace *) user;
    Packet *pkt;
    struct iphdr iph;
    int i, srcFound, dstFound;
    struct ether_header *ph;
    int realPktLength;
    int logPacket = 0;
    unsigned char ifaceConflict = 0;

    /*
     * nextIP is the last 2-bytes of the next available mapped IP address.
     * for each trace, it starts with X.X.1.1.  The first two bytes will be
     * assigned by the handler sending the packets.
     */
    static unsigned short nextIP;
    static unsigned short usedIPs[65536];
    unsigned char fileAddrType;

    /*
     * Since we do not replay non-IP traffic, just return
     */
    ph = (struct ether_header *) data;
    if (ph->ether_type != IP)
    {
        return;
    }

    if (pcap_hdr->caplen != pcap_hdr->len)
    {
        /*
         * This test indicates that the packet read from the PCAP file is not
         * the whole packet that was traveling along the wire when the pcap was 
         * recorded.  This probably means that the snaplen flag was not set to 
         * capture the whole packet when the pcap file was generated.
         * (see 'man tcpdump').
         */

        /*
         * If we are not in log mode, quit now.  If we are, set the local flag (logPacket)
         * to write the packet info to the log file and the global flag (isBadPcap)
         * and keep reading.  We'll quit later.
         */
        if (!logMode)
        {
            fprintf(stderr, "Invalid pcap: Complete packet not stored in file "
                    "(time: %ld.%ld, %d bytes on wire, %d bytes in file)\n",
                    (long) pcap_hdr->ts.tv_sec, (long) pcap_hdr->ts.tv_usec,
                    pcap_hdr->len, pcap_hdr->caplen);
            exit(-1);
        }
        else
        {
            logPacket = 1;
            isBadPcap = 1;
        }
    }

    /* Get the IP header */
    memcpy(&iph, data + 14, sizeof(iph));

    /*
     * Before going on, make sure we can replay the frame properly.
     * If we are modifying the IP addresses, tomahawk does not remap
     * multicast, traffic to 0.0.0.0, and 255.255.255.255.
     */
    if (modAddrs && !CanRewriteIP(&iph))
    {
        if (debugFlag)
        {
            struct in_addr srcIP, dstIP;
            srcIP.s_addr = iph.saddr;
            dstIP.s_addr = iph.daddr;
            if (logFile == (FILE *) NULL)
            {
                printf("LoadPacket: Skipping protocol Id %d, src: %s, ", iph.protocol, inet_ntoa(srcIP));
                printf("dst: %s (IP id: %u)\n", inet_ntoa(dstIP), ntohs(iph.id));
                fflush(stdout);
            }
            else
            {
                fprintf(logFile, "LoadPacket: Skipping protocol Id %u, src: %s, ",
                        ntohs(iph.protocol), inet_ntoa(srcIP));
                fprintf(logFile, "dst: %s (IP id: %u)\n", inet_ntoa(dstIP), ntohs(iph.id));
                fflush(logFile);
            }
        }
        return;
    }

    if (trace->numPkts == 0)
    {
        /*
         * Estimate the size of the packet array
         */
        trace->maxPkts = trace->size / AVERAGE_PACKET_SIZE;
        trace->maxPkts = max(trace->maxPkts, 16);
        trace->pkt = calloc(sizeof(Packet), trace->maxPkts);

        /*
         * Initialize the mapped IP address for the trace (i.e., nextIP variable)
         */
        nextIP = 0x0101;

        /*
         * Initialize the usedIPs array and random seed
         */
        for (i = 0; i < 65536; i++)
        {
            usedIPs[i] = 0;
        }
        srand((unsigned) time(NULL));

    }
    else if (trace->numPkts == trace->maxPkts)
    {
        trace->maxPkts = trace->maxPkts * 2;
        trace->pkt = realloc(trace->pkt, trace->maxPkts * sizeof(Packet));
    }
    pkt = &trace->pkt[trace->numPkts++];
    /*
     * At this point, packet length does not include the FCS (even if one was in the pcap)
     */
    pkt->len = ntohs(iph.tot_len) + 14;
    pkt->sec = pcap_hdr->ts.tv_sec;
    pkt->usec = pcap_hdr->ts.tv_usec;

    /*
     * We'll get at least 60 bytes off the wire, even if we
     * send less than 60 bytes, because the minimum packet
     * size is 64 bytes (4 bytes of checksum).  Since we compare
     * 60 bytes, we need to allocate at least 60 bytes for the
     * buffer (using calloc) so that both ends have the same data.
     */
    realPktLength = pkt->len;
    if (pkt->len < 60)
    {
        pkt->len = 60;
    }

    /* Allocate 4 extra bytes to hold the FCS */
    pkt->buffer = calloc(1, pkt->len + ETHER_CRC_LEN);
    memcpy(pkt->buffer, data, realPktLength);

    /*
     * See if we have seen the IP addresses in the packet already.
     * If so, then we have already decided what interface the IP
     * is connected to, so save that information into the packet
     * structure for the current packet.
     */
    pkt->saddr = iph.saddr;
    pkt->daddr = iph.daddr;
    srcFound = 0;
    dstFound = 0;
    pkt->iface = NOT_ACTIVE;

    /*
     * First compare the soure IP in the current packet to the array
     * of known IP addresses.
     */

    for (i = 0; i < trace->numIPs; i++)
    {
        if (iph.saddr == trace->traceIP[i].addr)
        {
            /* The source IP in the packet matches an already seen IP address */
            srcFound = 1;

            /* Set the outgoing interface to the value for the known IP. */
            pkt->iface = trace->traceIP[i].iface;

            /* Copy the previously mapped IP address to the mapped source IP already calculated. */
            pkt->wireSrc = trace->traceIP[i].mapIp;
            break;
        }
    }
    for (i = 0; i < trace->numIPs; i++)
    {
        if (iph.daddr == trace->traceIP[i].addr)
        {
            /*
             * The destination IP in the packet matches an already seen IP address
             */
            dstFound = 1;

            /*
             * In warning mode, check whether the outgoing interface decision that was made 
             * based on the source IP for this packet conflicts with the decision that will be
             * made based on the destination IP
             */
            if ((debugFlag || warnMode) && pkt->iface != NOT_ACTIVE)
            {
                if (pkt->iface == trace->traceIP[i].iface)
                {
                    ifaceConflict = 1;
                    trace->warningCount++;

                    /*
                     * Since there could be thousands of warnings, keep track of how many have been reported
                     */
                    if (trace->warningCount < 10)
                    {
                        printf("WARNING: Outgoing interface for packet is not well-defined (ID %u).\n",
                               trace->numPkts);
                    }
                    else if (trace->warningCount == 10)
                    {
                        printf("WARNING: Suppressing additional outgoing interface warnings\n");
                        printf("(use -Z to see all the gory details).\n");
                    }
                }
            }

            /*
             * Since the IP is the destination for this packet, set the outgoing 
             * interface to the opposite of what the value was for the known IP.
             */
            pkt->iface = !trace->traceIP[i].iface;

            /*
             * Copy the previously mapped IP address to the mapped destination IP already calculated.
             */
            pkt->wireDst = trace->traceIP[i].mapIp;
            break;
        }
    }

    /*
     * If this is the first time we've seen this src addr,
     * add it to the appropriate interface list, depending on
     * whether it was the source or destination
     */
    if (!srcFound)
    {
        /*
         * If we are modifying IP addresses, calculate store the IP to use
         */
        if (modAddrs)
        {
            fileAddrType = IsBroadcast(iph.saddr);
            if ((fileAddrType & BCAST_255) || (fileAddrType & BCAST_0))
            {
                /*
                 * The file IP is some type of broadcast, map it to the same type
                 * of broadcast address suffix
                 */
                pkt->wireSrc = RewriteBroadcastSuffix(nextIP, iph.saddr);
                if (debugFlag)
                {
                    struct in_addr inIp, outIp;
                    inIp.s_addr = iph.saddr;
                    outIp.s_addr = __bswap_16(pkt->wireSrc) << 16;
                    printf("Mapped broadcast src address: fileIP: %s,", inet_ntoa(inIp));
                    printf(" wireSrc: %s\n", inet_ntoa(outIp));
                    fflush(stdout);
                }
            }
            else
            {
                /*
                 * If the user asked for random IPs, randomly pick the lower two 2 bytes
                 * (number between 1..65534).  Store the value as nextIP, so it won't be reused
                 * in the small chance that we later randomly pick the same address for the dest IP.
                 */
                if (randomizeIPs)
                {
                    /*
                     * Loop until we select a random IP that has not already been used
                     */
                    while (1)
                    {
                        nextIP = GetRandomLowerIP();
                        if (usedIPs[nextIP] == 0)
                            break;
                    }

                    /*
                     * Since we'll be using this IP, change the flag for its index in the usedIPs array
                     */
                    usedIPs[nextIP] = 1;

                    pkt->wireSrc = nextIP;
                }
                else
                {

                    /*
                     * The file IP is not broadcast, so the wireIP should not be either.
                     */
                    pkt->wireSrc = nextIP;

                    /*
                     * nextIP was used, so increment it
                     */
                    nextIP = IncrAddr(nextIP, 1);
                }
            }
            /* 
             * Source address not found, add it to the trace. Do this at the end since the AddTraceIP
             * function gets the memory needed for the next trace.
             */
            AddTraceIP(trace, iph.saddr, IFACE_I, pkt->wireSrc);
        }
        else
        {
            /*
             * Add it to the trace.  No need to save the mapped IP when not modifying addresses
             */
            AddTraceIP(trace, iph.saddr, IFACE_I, 0);
        }
    }

    if (!dstFound)
    {
        /*
         * If we are modifying IP addresses, calculate store the IP to use
         */
        if (modAddrs)
        {
            fileAddrType = IsBroadcast(iph.daddr);
            if ((fileAddrType & BCAST_255) || (fileAddrType & BCAST_0))
            {
                /*
                 * The file IP is some type of broadcast, map it to the same type
                 * of broadcast address suffix
                 */
                pkt->wireDst = RewriteBroadcastSuffix(nextIP, iph.daddr);
                if (debugFlag)
                {
                    struct in_addr inIp, outIp;
                    inIp.s_addr = iph.daddr;
                    outIp.s_addr = __bswap_16(pkt->wireDst) << 16;
                    printf("Mapped broadcast dst address: fileIP: %s,", inet_ntoa(inIp));
                    printf(" wireSrc: %s\n", inet_ntoa(outIp));
                }
            }
            else
            {
                if (randomizeIPs)
                {
                    /*
                     * Loop until we select a random IP that has not already been used
                     */
                    while (1)
                    {
                        nextIP = GetRandomLowerIP();
                        if (usedIPs[nextIP] == 0)
                            break;
                    }

                    /*
                     * Since we'll be using this IP, change the flag for its index in the usedIPs array
                     */
                    usedIPs[nextIP] = 1;

                    pkt->wireDst = nextIP;
                }
                else
                {
                    /*
                     * The file IP is not broadcast, so the wireIP should not be either.
                     */
                    pkt->wireDst = nextIP;

                    /*
                     * nextIP was used, so increment it
                     */
                    nextIP = IncrAddr(nextIP, 1);
                }
            }
            /*
             * Destination address not found, add it to the trace
             */
            AddTraceIP(trace, iph.daddr, IFACE_J, pkt->wireDst);
        }
        else
        {
            /*
             * Add it to the trace.  No need to save the mapped IP when not modifying addresses
             */
            AddTraceIP(trace, iph.daddr, IFACE_J, 0);
        }
    }

    if (!srcFound && !dstFound)
    {
        pkt->iface = IFACE_I;
    }

    /*
     * Calculate the hash for the packet.
     */
    pkt->ipHash = HashIpData(iph.protocol, pkt->wireSrc, pkt->wireDst);

#ifdef DEBUG_SENDGROUP
    printf("DEBUG: Packet: %u\tipHash: %u\tinterface: %u\n", trace->numPkts - 1, pkt->ipHash, pkt->iface);
    LogPacketInfo(pkt, "");
#endif

    if (debugFlag && ifaceConflict)
    {
        /* Print a log message if the packet has ill-defined interface */
        LogPacketInfo(pkt, "has outgoing interface conflicts");
    }

    /*
     * Rewrite the mac addresses on the packet.
     */
    ph = (struct ether_header *) pkt->buffer;
    if (pkt->iface)
    {
        ph->ether_shost[0] = if1.eaddr[0];
        ph->ether_shost[1] = if1.eaddr[1];
        ph->ether_shost[2] = if1.eaddr[2];
        ph->ether_shost[3] = if1.eaddr[3];
        ph->ether_shost[4] = if1.eaddr[4];
        ph->ether_shost[5] = if1.eaddr[5];
        ph->ether_dhost[0] = if2.eaddr[0];
        ph->ether_dhost[1] = if2.eaddr[1];
        ph->ether_dhost[2] = if2.eaddr[2];
        ph->ether_dhost[3] = if2.eaddr[3];
        ph->ether_dhost[4] = if2.eaddr[4];
        ph->ether_dhost[5] = if2.eaddr[5];
    }
    else
    {
        ph->ether_dhost[0] = if1.eaddr[0];
        ph->ether_dhost[1] = if1.eaddr[1];
        ph->ether_dhost[2] = if1.eaddr[2];
        ph->ether_dhost[3] = if1.eaddr[3];
        ph->ether_dhost[4] = if1.eaddr[4];
        ph->ether_dhost[5] = if1.eaddr[5];
        ph->ether_shost[0] = if2.eaddr[0];
        ph->ether_shost[1] = if2.eaddr[1];
        ph->ether_shost[2] = if2.eaddr[2];
        ph->ether_shost[3] = if2.eaddr[3];
        ph->ether_shost[4] = if2.eaddr[4];
        ph->ether_shost[5] = if2.eaddr[5];
    }

    /* Compute the FCS on the Ethernet Frame
     * Some people say the hardare should do this, but it does not seem to.
     * Also for packets > 1510, the WriteInterface dies with a message too long error
     */
#ifdef DEBUG_FCS
    printf("packet length %u\n", pkt->len);
    fflush(stdout);

    /*
     * This section actually calculates the FCS, but it's not currently
     * working correctly, so I've commented it out.  The CRC32 function
     * needs to be verified.
     */
    if (pkt->len <= 1510)
    {
        unsigned int newFCS = CRC32(pkt->buffer, pkt->len);
        memcpy(&(pkt->buffer[pkt->len]), &newFCS, ETHER_CRC_LEN);
        pkt->len = pkt->len + ETHER_CRC_LEN;
    }

#endif
    /* Before we return, log the packet if it was bad */
    if (logPacket == 1)
        LogPacketInfo(pkt, "is truncated");

}

/*
 *----------------------------------------------------------------------
 *
 * FUNCTION LoadTrace --
 *
 *	Load a trace
 *
 * Returns:
 *	None
 *
 *----------------------------------------------------------------------
 */

Trace *LoadTrace(char *name, int loop, int maxActive, int timeout, int retrans, int modAddrs)
{
    pcap_t *in_file;
    Trace *trace;
    char ebuf[256];
    struct stat statBuf;

    if (modAddrs == 0)
    {
        if (maxActive > 1)
        {
            printf("Warning: file %s:\n   with -A 0 flags, only -n 1 is" " supported\n", name);
            maxActive = 1;
        }
    }
    in_file = pcap_open_offline(name, ebuf);
    if (!in_file)
    {
        fprintf(stderr, "Error opening %s for reading\n", name);
        fprintf(stderr, "in_file: %s\n", ebuf);
        exit(1);
    }
    trace = (Trace *) calloc(sizeof(Trace), 1);
    // Preserve (trace);
    stat(name, &statBuf);
    trace->size = statBuf.st_size;
    strncpy(trace->filename, name, sizeof(trace->filename));
    trace->traceIP = calloc(sizeof(TraceIP), 16);
    trace->numIPs = 0;
    trace->maxIPs = 16;
    trace->numPkts = 0;
    trace->maxPkts = 0;
    trace->pkt = NULL;
    trace->numActive = 0;
    trace->maxActive = maxActive;
    trace->modAddrs = modAddrs;
    trace->numComplete = 0;
    trace->maxComplete = loop;
    trace->timeout = timeout;
    trace->retrans = retrans;
    trace->completed = 0;
    trace->timedOut = 0;
    trace->retransCount = 0;
    trace->warningCount = 0;
    trace->createHandlerCb = NULL;
    trace->timedCreateHandlerCb = NULL;
    if (pcap_dispatch(in_file, -1, (void *) &LoadPacket, (u_char *) trace) == -1)
    {
        fprintf(stderr, "Error reading %s: %s\n", trace->filename, strerror(errno));
        // Release(trace);
        EventuallyFree(trace, NULL);
        return NULL;
    }
    pcap_close(in_file);

    /*
     * Exit if there was a truncated packet in the file
     */
    if (isBadPcap == 1)
    {
        fprintf(stderr, "Invalid pcap: There was a truncated packet in the file.\n");
        exit(1);
    }

    /*
     * Exit if there are no packets in the file that we could replay
     */
    if (trace->numPkts == 0)
    {
        fprintf(stderr, "Error: %s is empty\n", name);
        exit(1);
    }
    else if (trace->numIPs > MAX_UNIQUE_IPS)
    {
        /*
         * Exit if there are too many unique IP addresses
         */
        fprintf(stderr, "Error: %s has %d unique IP addresses (exceeds allowable amount: %d)\n",
                name, trace->numIPs, MAX_UNIQUE_IPS);
        exit(1);
    }

    trace->next = traceList;
    traceList = trace;

    if (debugFlag || warnMode)
    {
        unsigned int i;
        for (i = 0; i < trace->numPkts; i++)
        {
            if (trace->pkt[i].wireSrc == trace->pkt[i].wireDst)
            {
                struct in_addr srcIP, dstIP;
                srcIP.s_addr = trace->pkt[i].saddr;
                dstIP.s_addr = trace->pkt[i].daddr;
                fprintf(stderr, "Error: %s has packet with wire srcIP equal to wire dstIP\n", name);
                fprintf(stderr, "\tfile: srcIP = %s, ", inet_ntoa(srcIP));
                fprintf(stderr, "dstIP = %s\n", inet_ntoa(dstIP));
                exit(1);
            }
        }
    }
    return trace;
}

/*
 *----------------------------------------------------------------------
 *
 * FUNCTION FakeRecv/ReadPacket/RecvPacket --
 *
 *	These functions receive a packet from an interface.
 *	 - FakeRecv is called as an idle callback when playMode = 1
 *	   (i.e., play but don't recv packets).  It's simply calls RecvPacket
 *       - ReadPacket is called when the read FD is ready
 *       - RecvPacket is called with the actual packet from ReadPacket
 *
 * Debugged:  NO
 *
 * Returns:
 *	None
 *
 *----------------------------------------------------------------------
 */

void FakeRecv(void *data)
{
    RecvRecord *rr = (RecvRecord *) data;
    Handler *h;

    /*
     * We need this check in case the handler
     * is deleted before FakeRecv is called.  This
     * can happen because of retries.
     */
    for (h = handlerList; h != NULL; h = h->next)
    {
        if (handlerList == rr->h)
        {
            RecvPacket(data, NULL, NULL);
            return;
        }
    }
}

void RecvPacket(u_char * data, const struct pcap_pkthdr *pcap_hdr, const u_char * packetData)
{
    Handler *h;
    Trace *t;
    int i, found;
    RecvRecord *rr;
    unsigned int pktId;

    /*
     * If we're in tcpreplay mode, crack the RecvRecord packet
     * otherwise, find the handler associated with the packet.
     * If we can't find one, just return.
     */
    if (playMode == 1 || (logMode && packetData == NULL))
    {
        rr = (RecvRecord *) data;
        h = rr->h;
        free(data);
    }
    else
    {
        /*
         * Get the ID of the handler that sent the packet.  The return value will
         * be NULL if more than one tomahawk instance is running, and the ID of the
         * received packet is out of the range of IDs that this instance is responsible
         * for.  In this case, return (i.e., ignore the packet)
         */
        h = GetHandler(packetData, pcap_hdr->caplen, modAddrs, startHandlerId, endHandlerId);
        if (h == NULL)
        {
            if (debugFlag > 2)
            {
                printf("Got packet with no handler\n");
            }
            return;
        }

        /* Increment the global received packet count */
        numRecv++;
    }

    t = h->trace;
    found = 0;

    if (h->numTracePktsRecv < t->numPkts)
    {

        /*
         * Loop through the pktsOut Group and see if the received packet matches one in it
         */
        for (i = 0; i < h->numPktsSent; i++)
        {
            pktId = h->pktsOut[i];

            /*
             * Ignore if we've already received it.  We can't just
             * break because the trace might contain two identical
             * packets.
             */

            if (h->flags[pktId] & RECV)
            {
                continue;
            }

            /* See if the packet we received matches one in the group */
            if (playMode == 0 && !(logMode || packetData == NULL))
            {
                if (!PacketEqual(&t->pkt[pktId], packetData, pcap_hdr->caplen, pcap_hdr->len))
                {
                    continue;
                }
            }

            if (debugFlag)
            {
                double dt;
                dt = ReadSysClock() - startTime;
                printf("RecvPacket dt: %1.3f\ti: %u\th->id %u\n", dt, pktId, h->id);
            }

            /* If we got here, the packet matched with the one in the group that has index i */
            found++;

            /*
             * Mark the packet as received, update the number of packets received for
             * send group and the total number received for this trace.
             */
            h->flags[pktId] |= RECV;
            h->numPktsRecv++;
            h->numTracePktsRecv++;
            h->progressMade = 1;

            /* Update the state table that tracks the outstanding flows */
            assert(h->flowsOutStateTable[t->pkt[pktId].ipHash].numPkts > 0);
            h->flowsOutStateTable[t->pkt[pktId].ipHash].numPkts--;
            if (h->flowsOutStateTable[t->pkt[pktId].ipHash].numPkts == 0)
            {
                h->flowsOutStateTable[t->pkt[pktId].ipHash].iface = NOT_ACTIVE;
                h->flowsOutStateTable[t->pkt[pktId].ipHash].otherHostSeen = 0;
                h->numFlowsInGroup--;
            }

            break;
        }
    }

    /*
     * If we went through the whole pktsOut array and found is still 0, that 
     * means the received packet does not match any of the packets in the 
     * outstanding packet group.  Return to read the next packet from the interface.
     */
    if (!found)
    {
        return;
    }

    /*
     * We made progress.  Update the flag used for checking timeouts
     * and reset the retransmission counter
     */
    h->retrans = t->retrans;

    /*
     * If we've reached the end of the trace the clean up
     */
    assert(h->numTracePktsRecv <= t->numPkts);
    if (h->numTracePktsRecv == t->numPkts)
    {
        t->completed++;
        FinishHandler(h, 0);
        return;
    }

    /*
     * If we have not received all the packets in the send group,
     * return to read the next packet from the interface.
     */
    assert(h->numPktsRecv <= h->numPktsSent);
    if (h->numPktsRecv != h->numPktsSent)
    {
        return;
    }

    /*
     * All the packets in the send group have been received.  Get the next group.
     */
    CreatePacketSendGroup(h);

    SendPackets(h);
}

void ReadPacket(void *data)
{
    Interface *interface = (Interface *) data;
    struct sockaddr from;
    socklen_t fromlen;
    int flags;
    int len, fd;
    u_char buffer[100];
    struct pcap_pkthdr pcap_hdr;
#ifdef DEBUG_RECV
    uint32_t *y1, *y2;
#endif
    uint16_t *x1, *x2;

#ifdef DEBUG_RECV
    y1 = (uint32_t *) buffer;
    y2 = (uint32_t *) interface->eaddr;
#endif
    x1 = (uint16_t *) buffer;
    x2 = (uint16_t *) interface->eaddr;

    fromlen = sizeof(from);
    fd = interface->fd;
    flags = fcntl(fd, F_GETFL);
    fcntl(fd, F_SETFL, O_NONBLOCK);
    while (1)
    {
        len = recvfrom(fd, buffer, sizeof(buffer), MSG_TRUNC, &from, &fromlen);
        if (len <= 0)
        {
            break;
        }

        /*
         * Toss packets not sent to us (we get the packets we sent,
         * even if the interface isn't in promicuous mode).
         *
         * 
         *
         *  y1[0] = first 4 bytes of the destination MAC address in the packet read from the wire
         *  x1[2] = last 2 bytes of the destination MAC address in the packet read from the wire
         *  y2[0] = first 4 bytes of the MAC address of the interface packet was read from
         *  x2[2] = last 2 bytes of the MAC address of the interface packet was read from
         */

#ifdef DEBUG_RECV
        printf("fd=%d\ty1[0]=%x,y2[0]=%x,x1[2]=%x,x1[2]=%x,x1[9]=%x\n",
               fd, ntohl(y1[0]), ntohl(y2[0]), ntohs(x1[2]), ntohs(x2[2]), ntohs(x1[9]));
        fflush(stdout);
#endif
        if (memcmp(x1, x2, 6))
/*	if ( (x1[2] != x2[2]) || (y1[0] != y2[0]) ) */
        {
            continue;
        }
        if (len > sizeof(buffer))
        {
            pcap_hdr.caplen = sizeof(buffer);
        }
        else
        {
            pcap_hdr.caplen = len;
        }
        pcap_hdr.len = len;
        RecvPacket(data, &pcap_hdr, buffer);
    }
    fcntl(fd, F_SETFL, flags);
    interface->numOutstanding = 0;
    interface->progress++;
}

/*
 *----------------------------------------------------------------------
 *
 * FUNCTION RetrySendPackets/SendPackets --
 *
 *      Send the next batch of packets of a handler.
 *      The retry version is called by a timeout callback.
 *
 * Returns:
 *      None
 *
 *----------------------------------------------------------------------
 */

static void RetrySendPackets(void *data)
{
    Handler *h = (Handler *) data;
    h->timeoutCb = NULL;
    h->runState = RUNNING;
    SendPackets(data);
}

void SendPackets(void *data)
{
    Handler *h = (Handler *) data;
    Trace *t = h->trace;
    Packet *p = t->pkt;
    int offset, i, status;
    struct iphdr iph;
    struct tcphdr tcph;
    struct udphdr udph;
    char save[256];
    int hlen;
    int toSend = 0;
    double dt = 0;
    double dtRate = 0;

    /*
     * If we're not running, create a timer to try again in 25 msec
     * and return.  We'll continue to process receive packets, we
     * just won't generate any new packets.
     */
    if (h->runState == STOPPED)
    {
        if (h->timeoutCb == NULL)
        {
            h->timeoutCb = CreateTimerCallback(25, RetrySendPackets, data, NULL);
        }
        return;
    }

    /*
     * We need the dt value if we are debugging or rate-limiting)
     */
    if (debugFlag || desiredRate > 0)
    {
        dt = ReadSysClock() - startTime;
    }

    /*
     * If a desired rate was specified, see if we're above it.  If so, don't 
     * send anything;  Just set the runState to STOPPED and try again after 1 msec.
     */
    if (desiredRate > 0)
    {
        double x;
        dtRate = ReadSysClock() - rateCheckTime;
        x = (desiredRate * 1000000.0 / 8.0);
        x = x * dtRate;
        x = x - bytesSent;
        if (x > 1000000000.0)
        {
            x = 1000000000.0;
        }
        toSend = x;

        if (toSend < 0)
        {
            h->runState = STOPPED;
            if (debugFlag > 1)
            {
                printf("STOPPED: 1\n");
            }
            if (h->timeoutCb == NULL)
            {
                h->timeoutCb = CreateTimerCallback(1, RetrySendPackets, data, NULL);
            }
            return;
        }
    }

    if (debugFlag > 1)
    {
        printf("RUNNING\n");
    }

    /* Before sending the packet group, reset the progress flag to zero */
    h->progressMade = 0;

    /* Initialize the return status for the NIC */
    status = 0;

    /*
     * Send all the packets in the send group
     */
    for (i = 0; i < h->numPktsSent; i++)
    {
        unsigned int pktId = h->pktsOut[i];

        /*
         * Skip those packets we've already sent
         */
        if (h->flags[pktId] & SENT)
        {
            continue;
        }

        /*
         * Rewrite the IP addresses on the packet and adjust
         * the checksum.
         */
        memcpy(&iph, p[pktId].buffer + 14, sizeof(iph));
        hlen = 20 + (iph.ihl << 2);
        assert(hlen < sizeof(save));
        memcpy(&save, p[pktId].buffer + 14, hlen);
        if (t->modAddrs)
        {
            iph.saddr = GetWireIP(h->id, p[pktId].wireSrc, p[pktId].saddr, firstByte);
            iph.daddr = GetWireIP(h->id, p[pktId].wireDst, p[pktId].daddr, firstByte);

            /*
             * Incremental checksum calculation (RFC 1624)
             */
            iph.check = NewChecksum(iph.check, p[pktId].saddr, iph.saddr);
            iph.check = NewChecksum(iph.check, p[pktId].daddr, iph.daddr);
            memcpy(p[pktId].buffer + 14, &iph, sizeof(iph));

            /* If the packet is not a fragment, we need to rewrite the TCP or UDP
             * header checksum, too
             */

            if (!(iph.frag_off & htons(IP_OFFSET)))
            {

                offset = (iph.ihl << 2) + 14;
                switch (iph.protocol)
                {
                    case IPPROTO_TCP:
                        memcpy(&tcph, p[pktId].buffer + offset, sizeof(tcph));
                        tcph.th_sum = NewChecksum(tcph.th_sum, p[pktId].saddr, iph.saddr);
                        tcph.th_sum = NewChecksum(tcph.th_sum, p[pktId].daddr, iph.daddr);
                        memcpy(p[pktId].buffer + offset, &tcph, sizeof(tcph));
                        break;

                    case IPPROTO_UDP:

                        /*
                         * Per RFC 1122, 4.1.3.4 indicates that it is optional to
                         * include a UDP checksum.  If not, the value should be zero.
                         * So check if the sum is zero before rewriting it.  If so,
                         * leave it zero.
                         */
                        memcpy(&udph, p[pktId].buffer + offset, sizeof(udph));
                        if (udph.uh_sum != 0)
                        {
                            udph.uh_sum = NewChecksum(udph.uh_sum, p[pktId].saddr, iph.saddr);
                            udph.uh_sum = NewChecksum(udph.uh_sum, p[pktId].daddr, iph.daddr);
                            memcpy(p[pktId].buffer + offset, &udph, sizeof(udph));
                        }
                        break;
                }
            }
        }

        /* 
         * Send the packets out the appropriate interface.  Note that the MAC
         * addresses for the packets were rewritten in the LoadTrace function
         * assuming that IFACE_I packets go out if1 (i.e., eth0 or -i).
         */
#ifdef DEBUG_FCS
        printf("%u packet length %u\n", pktId, p[pktId].len);
        fflush(stdout);
#endif
        if (h->flowsOutStateTable[p[pktId].ipHash].iface)
        {
            status = WriteInterface(&if1, p[pktId].buffer, p[pktId].len);
        }
        else
        {
            status = WriteInterface(&if2, p[pktId].buffer, p[pktId].len);
        }
        memcpy(p[pktId].buffer + 14, &save, hlen);
        if (status < 0)
        {
            if ((errno == ENOBUFS) || (errno == EAGAIN))
            {
                break;
            }
            perror("WriteInterface");
            exit(1);
        }

        /*
           The packet was sent successfully.  
           * Update the packet status in the flags array
         */
        h->flags[pktId] |= SENT;
        if (debugFlag)
        {
            printf("Sent packet dt: %1.3f\ti: %u\th->id %u\tinterface %u\n",
                   dt, pktId, h->id, h->flowsOutStateTable[p[pktId].ipHash].iface);
        }

        /*
         * If we're in "play only" mode, then immediately mark the
         * packet as received
         */
        if (playMode == 1)
        {
            RecvRecord *rr;

            rr = malloc(sizeof(RecvRecord));
            rr->h = h;
            rr->packetNum = pktId;
            CreateIdleCallback(FakeRecv, rr, NULL);
        }

        /*
         * If a desiredRate was set, see if we've sent
         * as many bytes as we need to.  If so, break
         */
        if (desiredRate > 0)
        {
            bytesSent += p[pktId].len;
            toSend -= p[pktId].len;
            if (toSend < 0)
            {
                break;
            }
        }
    }

    /*
     * See if we need to reset the number of bytes sent.  This number is used
     * to calculate the average rate of sending packets that will be compared
     * to the average rate asked for by the user when deciding whether to 
     * set the Handler state to STOPPED.  Every second,
     * we reset the average so the actual output rate will be smoother.
     */
    if (desiredRate > 0 && dtRate > 1000000.0)
    {
        rateCheckTime = ReadSysClock();
        bytesSent = 0;
    }

    /* We sent all the unsent packets in the group.  Start the timeout clock */
    h->sendTime = Clicks();

    /*
     * If we get a recoverable error, try again in a 5 msec.
     * If we stopped because of rate limiting, try again in 1 msec
     * In either case, we've hit a limit, so indicate that we're
     * stalled.
     */
    if (status < 0 && h->timeoutCb == NULL)
    {
        h->runState = STOPPED;
        if (debugFlag > 1)
        {
            printf("STOPPED: 2\n");
        }
        h->timeoutCb = CreateTimerCallback(5, RetrySendPackets, h, NULL);
    }
    if (toSend < 0 && h->timeoutCb == NULL)
    {
        h->runState = STOPPED;
        if (debugFlag > 1)
        {
            printf("STOPPED: 3\n");
        }
        h->timeoutCb = CreateTimerCallback(1, RetrySendPackets, data, NULL);
    }
}

/*
 *----------------------------------------------------------------------
 *
 * FUNCTION ResendPackets --
 *
 *      This function is called when a packet send group has timed out.
 *	Packets in the group that were SENT but not RECV are flagged
 *	as not SENT.
 *
 * Returns:
 *      None
 *
 *----------------------------------------------------------------------
 */

void ResendPackets(Handler * h)
{
    int i;
    Trace *t;

    t = h->trace;
    for (i = 0; i < h->numPktsSent; i++)
    {

        unsigned int pktId = h->pktsOut[i];

        if (h->flags[pktId] & RECV)
        {
            continue;
        }
        if (h->flags[pktId] & SENT)
        {
            h->flags[pktId] &= ~SENT;
            t->retransCount++;
        }
    }

    SendPackets(h);
}

/*
 *----------------------------------------------------------------------
 *
 * FUNCTION LogPacketInfo --
 *
 *      Write out packet information for a given packet number.
 *	(i.e., protocol, src and dest IP and ports)
 *
 * Returns:
 *      None
 *
 *----------------------------------------------------------------------
 */

void LogPacketInfo(Packet * pkt, char *msg)
{
    struct iphdr iph;
    struct tcphdr tcph;
    struct udphdr udph;
    struct in_addr srcIP, dstIP;
    char protocolName[8];       /* Stores the human readable protocol UDP,TCP, etc */
    u_int16_t srcPort = 0, dstPort = 0;

    memcpy(&iph, pkt->buffer + 14, sizeof(iph));
    int offset = (iph.ihl << 2) + 14;

    /*
     * Determine the protocol and get the source and dest port, if possible
     */
    switch (iph.protocol)
    {
        case IPPROTO_TCP:
            memcpy(&tcph, pkt->buffer + offset, sizeof(tcph));
            srcPort = ntohs(tcph.th_sport);
            dstPort = ntohs(tcph.th_dport);
            strcpy(protocolName, "TCP");
            break;

        case IPPROTO_UDP:
            memcpy(&udph, pkt->buffer + offset, sizeof(udph));
            srcPort = ntohs(udph.uh_sport);
            dstPort = ntohs(udph.uh_dport);
            strcpy(protocolName, "UDP");
            break;

        case IPPROTO_ICMP:
            strcpy(protocolName, "ICMP");
            break;

        default:
            sprintf(protocolName, "%d", iph.protocol);
    }

    /*
     * For packets that are fragmented, but not the first fragment, there is no
     * src and destination port info in the packet
     */
    if (iph.frag_off & htons(IP_OFFSET))
    {
        srcPort = 0;
        dstPort = 0;
    }

    /*
     * Now print the information IP.  There are 2 printf statements because if there
     * is only one, the second call to inet_ntoa will overwrite the buffer from the 
     * first call before the src IP can be printed out, and the dstIP will be printed twice.
     */
    srcIP.s_addr = pkt->saddr;
    dstIP.s_addr = pkt->daddr;

    if (logFile == (FILE *) NULL)
    {
        printf("%s packet %s:%u-", protocolName, inet_ntoa(srcIP), srcPort);
        printf("%s:%u (IP id: %u", inet_ntoa(dstIP), dstPort, ntohs(iph.id));

        /*
         * If the packet was the first in a set of fragmented packets, print the IP ID
         */
        if (iph.frag_off & htons(IP_MF | IP_OFFSET))
        {
            printf(", fragment)");
        }
        else
        {
            printf(")");
        }
        printf(" %s.\n", msg);
        fflush(stdout);
    }
    else
    {
        fprintf(logFile, "%s packet %s:%u-", protocolName, inet_ntoa(srcIP), srcPort);
        fprintf(logFile, "%s:%u (IP id: %u", inet_ntoa(dstIP), dstPort, ntohs(iph.id));

        /*
         * If the packet was the first in a set of fragmented packets, print the IP ID
         */
        if (iph.frag_off & htons(IP_MF | IP_OFFSET))
        {
            fprintf(logFile, ", fragment)");
        }
        else
        {
            fprintf(logFile, ")");
        }
        fprintf(logFile, " %s.\n", msg);
        fflush(logFile);
    }

    return;
}

/*
 *----------------------------------------------------------------------
 *
 * FUNCTION CanRewriteIP --
 *
 *      Tests to see if the IP address is on that tomahawk can faithfully
 *	rewrite.  This means rewrite the IP without losing some of the
 *	characteristics of the traffic.  For example, currently multicast,
 *	all broadcast and all zero are skipped.
 *
 * Returns:
 *      1 if we can rewrite it
 *	0 if not
 *
 *----------------------------------------------------------------------
 */

unsigned char CanRewriteIP(struct iphdr *iph)
{
    /*
     * Only TCP, UDP and ICMP are properly supported 
     * Put TCP first in the list, since most traffic is TCP
     */
    if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP || iph->protocol == IPPROTO_ICMP)
    {
        /* 
         * Inside here, it's first match and you're out.  To maximize
         * performance, the conditions that are encountered most often
         * should appear first 
         *
         * Check the source or destination address is 0.0.0.0
         * 255.255.255.255 then we can't rewrite it.  Just check
         * the last byte (in network order)
         */
        if ((iph->saddr & 0xFF) == 0xFF)
            return 0;           /* highest byte is 255  */
        if ((iph->daddr & 0xFF) == 0xFF)
            return 0;           /* 255.X.X.X        */

        if ((iph->saddr & 0xFF) == 0x00)
            return 0;           /* highest byte is 0    */
        if ((iph->daddr & 0xFF) == 0x00)
            return 0;           /* 0.X.X.X      */

        return 1;

    }

    /* If we got here, we can't replay it   */
    return 0;
}

/*
 *----------------------------------------------------------------------
 *
 * FUNCTION CheckTimeouts --
 *
 *      Walk down the handler list, checking for any handlers that
 *      haven't made progress in the last
 *
 * Returns:
 *      None
 *
 *----------------------------------------------------------------------
 */

void CheckTimeouts(void *data)
{
    Handler *h, *next;
    unsigned long long int dt, now;

    now = Clicks();

    for (h = handlerList; h != NULL; h = next)
    {
        next = h->next;

#ifdef DEBUG_TIMEOUT
        printf("DEBUG: CheckTimeouts: hid %u (h->progressMade %u, h->numPktsSent %u)\n",
               h->id, h->progressMade, h->numPktsSent);
        fflush(stdout);
#endif

        /*
         * If the progressMade flag is set to 0
         * and we've waited the timeout period, resend the packet group
         */
        if (h->progressMade)
        {

#ifdef DEBUG_TIMEOUT
            printf("DEBUG: CheckTimeouts: hid %u made progress\n", h->id);
            fflush(stdout);
#endif

            /*
             * Progress has been made by this handler since the last timeout check
             * Reset the progress flag to zero and continue to the next hanlder
             */
            h->progressMade = 0;
            continue;
        }
        else
        {

            /*
             * For convenience, define some pointers to Handler structure members
             */
            Trace *t = h->trace;
            Packet *p = t->pkt;

            /*
             * Sent a packet group, but haven't received any unsent packets
             * check timeouts
             */
            dt = 1 + (now - h->sendTime) / clicksPerUSec / 1000;

            if (dt > t->timeout)
            {
                h->retrans--;
                if (debugFlag)
                {
                    printf("Resend dt:%lld\th->id %u\n", dt, h->id);
                }
                if (h->retrans == 0)
                {
                    char message[64];
                    sprintf(message, "timed out");

                    /*
                     * We did not receive all the packets we expected to receive within the
                     * timeout period.  Increment the timeout counter and log info about the
                     * unreceived packets.
                     */
                    t->timedOut++;
                    if (debugFlag)
                    {
                        printf("HandlerTimeout: %u\n", h->id);
                    }

                    if (logMode)
                    {

                        /*
                         * In log mode, the packet group size (i.e., maxOutstanding) should 
                         * be set to one (see main()).  The packet ID of the unreceived
                         * packet should be equal to the value of lowestUnsentPktId minus 1
                         */

                        unsigned int unrecvPktId = h->lowestUnsentPktId - 1;

                        /* Get the wire IP to include in the log message */
                        if (t->modAddrs)
                        {
                            char buffer[48];
                            struct in_addr charIP;
                            charIP.s_addr =
                                GetWireIP(h->id, p[unrecvPktId].wireSrc, p[unrecvPktId].saddr, firstByte);
                            sprintf(buffer, " (Wire IP: src %s, ", inet_ntoa(charIP));
                            strcat(message, buffer);
                            charIP.s_addr =
                                GetWireIP(h->id, p[unrecvPktId].wireDst, p[unrecvPktId].daddr, firstByte);
                            sprintf(buffer, "dst %s)", inet_ntoa(charIP));
                            strcat(message, buffer);
                        }

                        if (!quiet)
                        {
                            printf("Expected Packet Not Received (pktId %u of %u).\n", unrecvPktId,
                                   t->numPkts);
                        }
                        LogPacketInfo(&(p[unrecvPktId]), message);

                        /*
                         * Mark the packet as received
                         */
                        RecvRecord *rr;
                        rr = malloc(sizeof(RecvRecord));
                        rr->h = h;
                        rr->packetNum = unrecvPktId;
                        CreateIdleCallback(FakeRecv, rr, NULL);
                    }
                    else
                    {
                        /*
                         * If we are not in Log Mode, a timeout is a fatal error for the Handler.
                         * Also, the packet group size will be greater than 1, so it is possible
                         * many packets in the group may have been unreceived.  In debug mode,
                         * loop through the send group and log packet information on any unreceived
                         * packets.
                         */

                        if (debugFlag)
                        {
                            printf
                                ("List of expected Packet(s) that were not received in the send group that timed out:\n");
                            int i;
                            for (i = 0; i < h->numPktsSent; i++)
                            {
                                unsigned int pktId = h->pktsOut[i];

                                if (h->flags[pktId] & RECV)
                                {
                                    continue;
                                }
                                LogPacketInfo(&(p[pktId]), message);
                            }
                        }

                        /* Stop the handler */
                        FinishHandler(h, 1);
                    }

                }
                else
                {
                    /*
                     * There was a timeout, but the allowed number of retransmission has not
                     * been exceeded.  Time to retransmit the unreceived packets in the packet
                     * group.
                     *
                     */
#ifdef DEBUG_TIMEOUT
                    printf("DEBUG: CheckTimeouts: hid %u resending packets\n", h->id);
                    fflush(stdout);
#endif
                    ResendPackets(h);
                }
#ifdef DEBUG_TIMEOUT
            }
            else
            {
                printf("DEBUG: CheckTimeouts: hid %u no progress. no timeout.\n", h->id);
                fflush(stdout);
#endif
            }
        }
    }

    /*
     * We have checked all the Handlers and there was none that needed attention.
     * Check again in 100 ms
     */

    timeoutCB = CreateTimerCallback(100, CheckTimeouts, NULL, NULL);
}

/*
 *----------------------------------------------------------------------
 *
 * FUNCTION main --
 *
 *	Main routine
 *
 * Returns:
 *	None
 *
 *----------------------------------------------------------------------
 */

int main(int argc, char *argv[])
{
    char *interface1;
    char *interface2;
    extern char *optarg;
    extern int optind;
    int ch, files = 0;
    Trace *trace;
    int timeout;
    int retrans;
    int traceMaxActive;
    int numFiles;
    int loop;
    unsigned char maxActiveSpecified = 0;

    Calibrate();
    numFiles = 0;
    traceMaxActive = 1;
    timeout = 20;
    retrans = 5;
    loop = (1 << 30);
    interface1 = "eth0";
    interface2 = "eth1";

    while ((ch = getopt(argc, argv, "qdZhWN:l:L:t:R:A:r:a:m:n:i:j:e:s:f:w:")) != -1)
    {
        switch (ch)
        {
            case 'N':
                maxActive = atoi(optarg);
                if (maxActive > MAX_ACTIVE_HANDLERS)
                    maxActive = MAX_ACTIVE_HANDLERS;
                maxActiveSpecified = 1;
                break;
            case 'q':
                quiet++;
                break;
            case 'Z':
                debugFlag++;
                break;
            case 'd':
                randomizeIPs++;
                break;
            case 'h':
                Usage(argv[0]);
                break;
            case 'W':
                warnMode = 1;
                break;
            case 'l':
                loop = atoi(optarg);
                break;
            case 'L':
                logMode = 1;
                if (strlen(optarg) != 0 && optarg[0] != '-')
                {
                    logFile = fopen(optarg, "a");
                    if (logFile == NULL)
                    {
                        fprintf(stderr, "Cannot open file for logging (%s).\n", optarg);
                        exit(1);
                    }
                }
                break;
            case 's':
                startHandlerId = atoi(optarg);
                if (startHandlerId == 0)
                {
                    fprintf(stderr, "Start ID can no tbe zero.\n");
                    exit(1);
                }
                maxHandlerIdInUse = startHandlerId - 1;
                break;
            case 'e':
                endHandlerId = atoi(optarg);
                break;
            case 't':
                timeout = atoi(optarg);
                break;
            case 'R':
                desiredRate = atof(optarg);
                break;
            case 'r':
                retrans = atoi(optarg);
                break;
            case 'A':
                modAddrs = atoi(optarg);
                break;
            case 'a':
                startAddr = optarg;
                firstByte = inet_addr(startAddr) & 0xFF;
                break;
            case 'm':
                maxOutstanding = atoi(optarg);
                if (maxOutstanding > MAX_PACKETS_OUTSTANDING)
                    maxOutstanding = MAX_PACKETS_OUTSTANDING;
                break;
            case 'n':
                traceMaxActive = atoi(optarg);
                break;
            case 'i':
                interface1 = optarg;
                break;
            case 'j':
                interface2 = optarg;
                break;
            case 'f':
                fileInfo[numFiles].name = optarg;
                fileInfo[numFiles].maxActive = traceMaxActive;
                fileInfo[numFiles].retrans = retrans;
                fileInfo[numFiles].timeout = timeout;
                fileInfo[numFiles].loop = loop;
                fileInfo[numFiles].modAddrs = modAddrs;
                numFiles++;
                break;
            case 'w':
                maxPcapLookAhead = atoi(optarg);
                if (maxPcapLookAhead > MAX_TRACE_LOOKAHEAD)
                    maxPcapLookAhead = MAX_TRACE_LOOKAHEAD;
                break;
            default:
                Usage(argv[0]);
        }
    }

    /*
     * In logMode, override some configuration settings regardless of what 
     * the user may have provided for them.
     *
     *  maxOutstanding (-m) - Maximum number of packets to send before confirming receipt.
     *          If this is not 1, tomahawk may miss some packets that timeout.
     *  maxActive (-N) - Maximum number of simultaneously active handlers.
     *  retrans (-r) - Number of retransmissions
     *  timeout (-t) - Timeout for 1 packet (just to speed things up a bit, since the
     *          code must wait one timeout after each transmission)
     */
    if (logMode)
    {
        maxOutstanding = 1;
        retrans = 1;
        maxActive = 1;
        timeout = 10;
        loop = 1;

        /*
         * For now, we allow only one file in log mode, so exit if more than one
         * was specified.
         */
        if (numFiles > 1)
        {
            fprintf(stderr, "Error: Only one file may be specified when running in log mode.\n");
            Usage(argv[0]);
        }
        else
        {
            /* Reset all the file specific values */
            fileInfo[0].retrans = retrans;
            fileInfo[0].maxActive = 1;
            fileInfo[0].timeout = timeout;
            fileInfo[0].loop = loop;
        }
    }

    /*
     * Initialize the active handlers list
     * IMPORTANT: 
     * When there is a limit of 1 active handler,
     * GetHandler assumes that ID will be startId.
     */
    if (maxActiveSpecified && (loop > maxActive) && ((endHandlerId - startHandlerId) < maxActive))
    {
        fprintf(stderr,
                "\nWarning: You have not provided enough handler IDs to support the maximum number of active handlers.\n");
        fprintf(stderr,
                "\t( end ID - start ID ) >= Number Simultaneous Active Handlers (i.e. %u - %u >= %d )\n\n",
                endHandlerId, startHandlerId, maxActive);
        fprintf(stderr,
                "\tEither limit the number of loops to replay (see '-l')\n\tor limit the maximum number of simultaneous handlers (see '-N').\n\n");
        Usage(argv[0]);
    }
    InitializeActiveHandlers(startHandlerId, endHandlerId);

    memset(if1.eaddr, 1, sizeof(if1.eaddr));
    memset(if2.eaddr, 2, sizeof(if2.eaddr));
    OpenInterface(interface1, &if1);
    OpenInterface(interface2, &if2);


    /*
     * Load all the input files, building up the traceList.
     * Send the trace filename to the peer, so they can
     * load it, too.
     */
    for (files = 0; files < numFiles; files++)
    {
        if (debugFlag || warnMode)
        {
            printf("\nLoading %s\n", fileInfo[files].name);
        }
        trace = LoadTrace(fileInfo[files].name,
                          fileInfo[files].loop,
                          fileInfo[files].maxActive,
                          fileInfo[files].timeout, fileInfo[files].retrans, fileInfo[files].modAddrs);
        CreateHandler(trace);
    }


    timeoutCB = CreateTimerCallback(100, CheckTimeouts, NULL, NULL);
    signal(SIGINT, HandleInterrupt);
    signal(SIGSEGV, HandleSegv);
    if (warnMode)
    {
        CleanUp();
        return 0;
    }

    if (!quiet)
    {
        printf("Beginning test\n");
    }
    bytesSent = 0;
    startTime = ReadSysClock();
    rateCheckTime = startTime;
    if (debugFlag > 1)
    {
        printf("RUNNING\n");
    }

    while (1)
    {
        DoOneEvent(1);
        if (traceList == NULL)
        {
            CleanUp();
        }
    }

    return 0;
}
