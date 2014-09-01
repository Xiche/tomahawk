/*
 * packetutil.c
 *
 * Copyright (c) 2002, 2003, 2004 TippingPoint Technologies.
 * All rights reserved.
 *
 * Please see LICENSE for licensing information
 */

#include "packetutil.h"

/* Handler *handlerList = NULL; */
Trace *traceList = NULL;
extern int debugFlag;

/* 
 * handlerIds table is used to keep track of the memory addresses for 
 * currently active handlers.  For handler.id=i, if activeHandlers[i]=NULL
 * then the handler with ID i is not in use.
 * IDs must be re-used since there is an upper limit of 254 (0 and 255 not used)
 */
static struct Handler *activeHandlers[MAX_ACTIVE_HANDLERS];

/*
 *----------------------------------------------------------------------
 *
 * FUNCTION InitializeActiveHandlers --
 *
 *      Initializes the activeHandlers array by setting available values
 *	to NULL.  Receives 2 arguments, the lowest ID to make available
 *	and the highest ID to make available.  IDs < startId and > endId
 *	will be not NULL, and therefore unusable.  If either value is
 *	0, there is no limit.
 *
 * Returns:
 *      NA
 *
 *----------------------------------------------------------------------
 */
void InitializeActiveHandlers(unsigned char startId, unsigned char endId)
{
    int i;

    /* Loop through the array and set values as appropriate */
    for (i = 0; i < MAX_ACTIVE_HANDLERS; i++)
    {
        if (i >= startId && i <= endId)
        {
            activeHandlers[i] = (struct Handler *) NULL;    /* Make ID available */
        }
        else
        {
            activeHandlers[i] = (Handler *) malloc(sizeof(Handler));    /* Reserve ID */
        }
    }

    return;
}

/*
 *----------------------------------------------------------------------
 *
 * FUNCTION AddHandlerId --
 *
 *      Adds the memory address of the handler to the activeHandlers array.
 *	Receives the ID and handler pointer and adds it to the array
 *
 * Returns:
 *      NA
 *
 *----------------------------------------------------------------------
 */
void AddHandlerId(int id, Handler * h)
{
    assert(id < MAX_ACTIVE_HANDLERS && activeHandlers[id] == (Handler *) NULL);
    activeHandlers[id] = h;
    return;
}

/*
 *----------------------------------------------------------------------
 *
 * FUNCTION GetHandlerId --
 *	Receives the memory location for a handler and determines the lowest
 *	available handler ID.  Also calls AddHandlerId to add the handler 
 *	to the activeHandlers array.
 *
 * Returns:
 *      Returns the lowest handler ID not in use
 *
 *----------------------------------------------------------------------
 */
unsigned short GetHandlerId(unsigned char loopStart, unsigned char loopEnd, Handler * h)
{
    int i;
    unsigned char foundId = 0;

    for (i = loopStart; i <= loopEnd; i++)
    {
        if (activeHandlers[i] == (Handler *) NULL)
        {
            foundId = 1;
            break;
        }
    }

    /* If we did not find an ID, return 0 */
    if (!foundId)
    {
        return 0;
    }

    /* Make sure we did not run off the end of the array */
    assert(i <= MAX_ACTIVE_HANDLERS);

    /* Add the handler ID to the activeHandler list */
    AddHandlerId(i, h);

    /* Return the ID */
    return (unsigned short) i;
}

/*
 *----------------------------------------------------------------------
 *
 * FUNCTION FreeHandlerId --
 *
 *      Free the memory address of the handler to the activeHandlers array.
 *	Receives a handler ID
 *
 * Returns:
 *      NA
 *
 *----------------------------------------------------------------------
 */
void FreeHandlerId(unsigned short id)
{
    assert(id < MAX_ACTIVE_HANDLERS);
    if (activeHandlers[id] != (Handler *) NULL)
    {
        activeHandlers[id] = (Handler *) NULL;
    }
    return;
}

/*
 *----------------------------------------------------------------------
 *
 * FUNCTION IsBroadcast --
 *
 *      Decide whether an IP address is a broadcast address.  Currently
 *	it only checks for 0 and 255.
 *
 * Returns:
 *      NOT_BCAST, BCAST_255, BCAST_0
 *
 *----------------------------------------------------------------------
 */

unsigned char IsBroadcast(in_addr_t inetAddr)
{
    /* First mask off each of the 8 bits of the address */
    unsigned int x1 = __bswap_32(inetAddr) & 0xFF;
    unsigned int x2 = __bswap_32(inetAddr) & 0xFF00;
    unsigned int x3 = __bswap_32(inetAddr) & 0xFF0000;
    unsigned int x4 = __bswap_32(inetAddr) & 0xFF000000;

    /* If the address landed on a broadcast */
    if (!(x1 ^ 0xFF) || !(x2 ^ 0xFF00) || !(x3 ^ 0xFF0000) || !(x4 ^ 0xFF000000))
    {
        return (BCAST_255);
    }

    if ((x1) && (x2) && (x3) && (x4))
    {
        return (NOT_BCAST);
    }

    if ((!(x1 ^ 0x0)) ||
        (!(x1 ^ 0x0) && !(x2 ^ 0x0)) ||
        (!(x1 ^ 0x0) && !(x2 ^ 0x0) && !(x3 ^ 0x0)) ||
        (!(x1 ^ 0x0) && !(x2 ^ 0x0) && !(x3 ^ 0x0) && !(x4 ^ 0x0)))
    {
        return (BCAST_0);
    }

    return (NOT_BCAST);
}

/*
 *----------------------------------------------------------------------
 *
 * FUNCTION RewriteBroadcastSuffix --
 *
 *      Ensures the last 2 bytes of a mapped IP address is a similar type 
 *	of broadcast to the original address.  For example, if the origAddr 
 *	was 129.109.255.155 the mapped address would also be X.X.255.255
 *
 * Returns:
 *      The lowest 2 bytes of the mapped address
 *
 *----------------------------------------------------------------------
 */
unsigned short RewriteBroadcastSuffix(unsigned short ipToRewrite, in_addr_t origAddr)
{
    /*
     * We are only interesed in the last 2 bytes of the original IP (N.N.X2.X1)
     * Remember it's stored in byte-swapped order
     */
    unsigned int x1 = __bswap_32(origAddr) & 0xFF;
    unsigned int x2 = __bswap_32(origAddr) & 0xFF00;

    /*
     * Check each 8 bit section for 255.  If any either is 255, change the corresponding
     * one in the mapped IP to 255
     */
    if (!(x1 ^ 0xFF))
    {
        ipToRewrite = ipToRewrite | 0xFF;
    }
    if (!(x2 ^ 0xFF00))
    {
        ipToRewrite = ipToRewrite | 0xFF00;
    }

    /*
     * Next check each 8 bit section for 0.  In this case, map to zero only if all the
     * ones to the right are also zero
     */
    if (!(x1 ^ 0x0))
    {
        /* zero out last byte */
        ipToRewrite = ipToRewrite & 0xFF00;
    }
    if (!(x1 ^ 0x0) && !(x2 ^ 0x0))
    {
        ipToRewrite = ipToRewrite & 0x00;
    }

    return ipToRewrite;
}

/*
 *----------------------------------------------------------------------
 *
 * FUNCTION IncrAddr/SubAddr --
 *
 *      Do arithmetic on IP addresses.
 *
 *      IncrAddr -- 
 *        Increment an IP address by a fixed value.  For example,
 *        10.0.0.5 + 10 = 10.0.0.15.  Overflow rolls into the next
 *        class C (or class B, or class A).
 *
 *      SubAddr --
 *        Return the difference (an int) between two IP addresses.
 *
 * Returns:
 *      None
 *
 *----------------------------------------------------------------------
 */

unsigned short IncrAddr(unsigned short x1, int n)
{
    in_addr_t tempAddr;
    x1 += n;
    tempAddr = (__bswap_16(x1) << 16);

    /*
     * Before returning check if this is a broadcast address.  If so,
     * increment again, as needed.
     */

    unsigned char addrType = IsBroadcast(tempAddr);
    while ((addrType & BCAST_255) || (addrType & BCAST_0))
    {
        x1++;
        tempAddr = (__bswap_16(x1) << 16);
        addrType = IsBroadcast(tempAddr);
    }

    return x1;
}

inline unsigned int SubAddr(unsigned int x1, unsigned int x2)
{
    x1 = __bswap_32(x1);
    x2 = __bswap_32(x2);
    return x1 - x2;
}

/*
 *----------------------------------------------------------------------
 *
 * FUNCTION GetHandler --
 *
 *      Gets the handler ID for a given mapped IP address.
 *
 * Returns:
 *      None
 *
 *----------------------------------------------------------------------
 */

inline
    Handler *
GetHandler(const u_char * packetData, int len, int modAddrs, unsigned char startId, unsigned char endId)
{
    struct iphdr iph;
    unsigned int wireIP;
    int i;

    memcpy(&iph, packetData + 14, sizeof(iph));
    wireIP = iph.daddr;

    if (modAddrs)
    {
        /* Get the handler ID from the 2nd byte of the IP address */
        i = (wireIP >> 8) & 0xFF;

        /* If the handler ID is not in the range we are responsible for, return NULL */
        if (i < startId || i > endId)
            return NULL;

        if (activeHandlers[i] != (Handler *) NULL)
            return activeHandlers[i];
    }
    else
    {
        /*
         * If we are not modifying addresses, there will always be only one handler
         * and the ID will always be startId
         */
        if (activeHandlers[startId] != (Handler *) NULL)
            return activeHandlers[startId];
    }

    return NULL;
}

/*
 *----------------------------------------------------------------------
 *
 * FUNCTION GetRandomLowerIP --
 *
 *	Generates a random short int and passes it to the NextIP function
 *	to make sure it's not a broadcast value
 *
 * Returns:
 *	Lower 2 bytes of a non-broadcast IP address (short int)
 *
 *----------------------------------------------------------------------
 */

unsigned short GetRandomLowerIP(void)
{
    unsigned short randIP;
    randIP = 1 + (unsigned short) (65530.0 * rand() / (RAND_MAX + 1.0));

    /*
     * Send nextIP to the IncrAddr function to be sure it's not a broadcast
     * address
     */
    return (IncrAddr(randIP, 1));

}

/*
 *----------------------------------------------------------------------
 *
 * FUNCTION AddTraceIP --
 *
 *	Add an IP address to the list of IP addresses in a trace as 
 *      connected to IFACE_I or IFACE_J.  Used by LoadPacket, typically.
 *
 * Returns:
 *	None
 *
 *----------------------------------------------------------------------
 */

void AddTraceIP(Trace * trace, in_addr_t addr, int iface, unsigned short mapIp)
{
    if (debugFlag > 2)
    {
        struct in_addr x;
        x.s_addr = addr;
        printf("Adding address '%s' as %s in traceIP table\n",
               inet_ntoa(x), (iface ? "iface1 (-i)" : "iface2 (-j)"));
    }

    if (trace->numIPs == trace->maxIPs)
    {
        if (trace->maxIPs == 0)
        {
            trace->maxIPs = 16;
            trace->traceIP = (TraceIP *) calloc(sizeof(TraceIP), trace->maxIPs);
        }
        else
        {
            if (trace->maxIPs < 1024)
            {
                trace->maxIPs *= 2;
            }
            else
            {
                trace->maxIPs += 1024;
            }
            trace->traceIP = (TraceIP *) realloc(trace->traceIP, sizeof(TraceIP) * trace->maxIPs);
        }
    }
    trace->traceIP[trace->numIPs].addr = addr;
    trace->traceIP[trace->numIPs].mapIp = mapIp;
    trace->traceIP[trace->numIPs].iface = iface;
    trace->numIPs++;
}

/*
 *----------------------------------------------------------------------
 *
 * FUNCTION ParseEtherAddr --
 *
 *	Parses the string representation of an Ethernet address
 *      into a 6 byte binary representation (same as occurs in the
 *      packet).
 *
 * Returns:
 *	1 if parse is successful, 0 otherwise.
 *
 *----------------------------------------------------------------------
 */

int ParseEtherAddr(char *ether, /* (IN)  Ethernet address, colon separated */
                   Mac dst)     /* (OUT) 6 bytes of address */
{
    int i = 0;
    char *temp;

    while (*ether && i < 6)
    {
        temp = ether;
        while (*ether && *ether != ':')
        {
            ether++;
        }
        if (*ether == ':')
        {
            ether++;
        }
        dst[i++] = (u_char) strtol(temp, NULL, 16);
    }
    return (i == 6);
}

/*
 *----------------------------------------------------------------------
 *
 * FUNCTION PrintBinary/PrintTime/PrintPacket/PrintTrace --
 *
 *	Utility functions for printing
 *      PrintTime arranges to call itself every 5 milliseconds via
 *      the event loop.
 *
 * Returns:
 *	None
 *
 *----------------------------------------------------------------------
 */

void PrintBinary(unsigned int n)
{
    int i;

    for (i = 31; i >= 0; i--)
    {
        if (n & (1 << i))
        {
            printf("1");
        }
        else
        {
            printf("0");
        }
    }
    printf("\n");
}

void PrintTime(void *data)
{
    static double start = 0.0;
    static int inited;

    if (!inited)
    {
        inited++;
        start = ReadSysClock();
    }
    printf("%1.6lf\n", ReadSysClock() - start);
    CreateTimerCallback(5, PrintTime, NULL, NULL);
}

void PrintPacket(int n, int iface, const u_char * buffer)
{
    int j;

    printf("packet %6d (interface=%d):\n", n, iface);
    if (debugFlag <= 2)
    {
        return;
    }
    for (j = 0; j < 64; j++)
    {
        printf("%02x ", buffer[j]);
        if ((j % 16) == 7)
        {
            printf(" ");
        }
        if ((j % 16) == 15)
        {
            printf("\n");
        }
    }
    printf("\n");
}

void PrintTrace(Trace * trace)
{
    int i;
    Packet *pkt;

    for (i = 0; i < trace->numPkts; i++)
    {
        pkt = &trace->pkt[i];
        PrintPacket(i, pkt->iface, pkt->buffer);
    }
}

void PrintHandlerSendGroup(Handler * h)
{
    printf("Current Handler Send Group\n");
    int i;
    for (i = 0; i < h->numPktsSent; i++)
    {
        unsigned int id = h->pktsOut[i];
        printf("i: %d\tPkt ID: %u\tflowHash: %u\tiface: %u\n", i, id, h->trace->pkt[id].ipHash,
               h->flowsOutStateTable[h->trace->pkt[id].ipHash].iface);
        fflush(stdout);
    }
    printf("%d packets. Lowest unsent packet ID is %u\n", h->numPktsSent, h->lowestUnsentPktId);
    printf("\n");
}

void PrintFlowsOutStateTable(Handler * h)
{
    printf("Current Handler Send flowsOutStateTable entries with non-default values\n");
    unsigned int i;
    for (i = 0; i < 65535; i++)
    {
        if (h->flowsOutStateTable[i].iface != NOT_ACTIVE || h->flowsOutStateTable[i].otherHostSeen != 0 ||
            h->flowsOutStateTable[i].numPkts != 0)
        {
            printf("flowHash: %u\tinterface: %u\totherHostSeen: %u\tnumPkts: %u\n", i,
                   h->flowsOutStateTable[i].iface, h->flowsOutStateTable[i].otherHostSeen,
                   h->flowsOutStateTable[i].numPkts);
            fflush(stdout);
        }
    }
    printf("\n");
}

/*
 *----------------------------------------------------------------------
 *
 * FUNCTION PacketEqual --
 *
 *	Return whether the first 52 bytes (typically, the
 *      MAC, IP, and TCP headers) of two packets are identical
 *      Ignore the IP addresses and checksums (those have been
 *      rewritten).
 *
 * Returns:
 *	None
 *
 *----------------------------------------------------------------------
 */

int PacketEqual(Packet * p, const u_char * data, int caplen, int actualLen)
{

    /*
     * Strategy is this:
     *  - Check the length of the packet, bail if not the same
     *  - Grab the ip header from the master packet and the data packet,
     *    zero the checksum, saddr, and daddr fields.  Add it to the buffers
     *  - Grab the L4 header from the master packet and the data packet.
     *    Zero any checksum field.  Add it to the buffers.
     *  - Copy any remaining L5 data into the buffers
     *  - Do a int by int compare of the buffers, starting from the end.
     *    Return 0 if nothing's equal
     */

    /*
     * If the packet lengths aren't equal, then the packets can't be equal
     */
    if (actualLen > 60 && p->len != actualLen)
    {
        return 0;
    }
    else
    {
        struct iphdr *iph;
        struct tcphdr *tcph;
        struct udphdr *udph;
        int offset;
        u_int16_t id;
        char b1[128], b2[128];
        int len, iphlen, rv;

        /*
         * Copy the ipheader into b1 (master), b2 (packet from wire)
         */
        memset(b1, 0, sizeof(b1));
        memset(b2, 0, sizeof(b2));

        memcpy(b1, p->buffer + 14, sizeof(struct iphdr));
        iph = (struct iphdr *) b1;
        iphlen = iph->ihl << 2;

        /*
         * Zero out some fields in the IP header that might be different between
         * master and wire packets
         * IP checksum, Src Addr, Dest Addr, TTL
         */
        memcpy(b1, p->buffer + 14, iphlen);
        iph->check = 0;
        iph->saddr = 0;
        iph->daddr = 0;
        iph->ttl = 0;
        id = iph->id;

        memcpy(b2, data + 14, iphlen);
        iph = (struct iphdr *) b2;
        iph->check = 0;
        iph->saddr = 0;
        iph->daddr = 0;
        iph->ttl = 0;

        /*
         * Do a quick check on the IP ids -- if not equal, return no match.
         */
        if (iph->id != id)
        {
            return 0;
        }

        /*
         * If the master is TCP or UDP, copy the TCP/UDP header
         * from the data and clear the checksum.
         */
        switch (iph->protocol)
        {
            case IPPROTO_TCP:
                memcpy(b1 + iphlen, p->buffer + iphlen + 14, sizeof(struct tcphdr));
                tcph = (struct tcphdr *) (b1 + iphlen);
                tcph->th_sum = 0;

                memcpy(b2 + iphlen, data + iphlen + 14, sizeof(struct tcphdr));
                tcph = (struct tcphdr *) (b2 + iphlen);
                tcph->th_sum = 0;

                offset = iphlen + sizeof(struct tcphdr);
                break;

            case IPPROTO_UDP:
                memcpy(b1 + iphlen, p->buffer + iphlen + 14, sizeof(struct udphdr));
                udph = (struct udphdr *) (b1 + iphlen);
                udph->uh_sum = 0;

                memcpy(b2 + iphlen, data + iphlen + 14, sizeof(struct udphdr));
                udph = (struct udphdr *) (b2 + iphlen);
                udph->uh_sum = 0;

                offset = iphlen + sizeof(struct udphdr);
                break;

            default:
                offset = iphlen;
                break;
        }

        /*
         * len is number of bytes to compare.  Max is 100
         */
        len = caplen - 14;
        if (len > 100)
        {
            len = 100;
        }

        if (len > offset)
        {
            memcpy(b1 + offset, p->buffer + offset + 14, len - offset);
            memcpy(b2 + offset, data + offset + 14, len - offset);
        }

        rv = (memcmp(b1, b2, len) == 0);
        return rv;
    }
}

/*
 *----------------------------------------------------------------------
 *
 * FUNCTION GetWireIP --
 *
 *      Find the on-the-wire IP of an address.  This function should only
 *	be called if the modify IP flag is set, so we'll assume it is.
 *	The last 2 bytes of the IP should be in the packet structure.
 *	The first byte is either constant or taken from the original
 *	address.  The second byte is the handler ID
 *
 * Returns:
 *	None
 *
 *----------------------------------------------------------------------
 */

in_addr_t
GetWireIP(unsigned short handlerId, unsigned short wireIPSuffix, in_addr_t addr,
          unsigned char startAddrByte)
{

    /* Assign the handler ID and wireIPSuffix to the address */
    unsigned int wireIP = (__bswap_16(wireIPSuffix) << 16) | (handlerId << 8);

    if (startAddrByte)
    {
        /*
         * if startAddrByte is not zero, use it for the first byte of the address
         */
        wireIP = wireIP | startAddrByte;
    }
    else
    {
        /*
         * Get the first byte from the original address
         */
        wireIP = wireIP | (addr & 0xFF);
    }

    return wireIP;
}

/*
 *----------------------------------------------------------------------
 *
 * FUNCTION NewChecksum --
 *
 *      Compute a checksum if a 32 bit value is replaced is a packet
 *      check: old checksum
 *      old: 32 bit to be replaced
 *      new: 32 bit to be inserted
 *
 * Returns:
 *      None
 *
 *----------------------------------------------------------------------
 */

inline unsigned short NewChecksum(unsigned short check, unsigned int old, unsigned int new)
{
    unsigned int m3, b, c, d, e;
    unsigned short a;

    a = ntohs(check);
    a = ~a;

    old = ntohl(old);
    old = ~old;
    b = old >> 16;
    c = old & 0xffff;

    new = ntohl(new);
    d = new >> 16;
    e = new & 0xffff;

    m3 = a + b + c + d + e;
    m3 = (m3 >> 16) + (m3 & 0xffff);
    m3 = (m3 >> 16) + (m3 & 0xffff);
    check = ~m3;
    return htons(check);
}

/*
 * The following two routines were lifted from
 *	http://www.hackersdelight.org/HDcode/newCode/crc.cc
 */

/*
 *----------------------------------------------------------------------
 *
 * FUNCTION reverse --
 *
 *	Reverses (reflects) bits in a 32-bit word.
 *
 * Returns:
 *      Reversed word
 *
 *----------------------------------------------------------------------
 */

unsigned Reverse(unsigned x)
{
    x = ((x & 0x55555555) << 1) | ((x >> 1) & 0x55555555);
    x = ((x & 0x33333333) << 2) | ((x >> 2) & 0x33333333);
    x = ((x & 0x0F0F0F0F) << 4) | ((x >> 4) & 0x0F0F0F0F);
    x = (x << 24) | ((x & 0xFF00) << 8) | ((x >> 8) & 0xFF00) | (x >> 24);
    return x;
}

// ----------------------------- --------------------------------

/*
 *----------------------------------------------------------------------
 *
 * FUNCTION crc32a --
 *
 *      Computes a 32 bit CRC of a message.  This is the basic CRC
 *	algorithm with no optimizations. It follows the
 *	logic circuit as closely as possible. 
 *
 * Returns:
 *      CRC of message
 *
 *----------------------------------------------------------------------
 */


unsigned int CRC32(unsigned char *message, int msgLength)
{
    int i, j;
    unsigned int byte, crc;

    i = 0;
    crc = 0xFFFFFFFF;
    while (i < msgLength)
    {
        byte = message[i];      // Get next byte.
        byte = Reverse(byte);   // 32-bit reversal.
        for (j = 0; j <= 7; j++)
        {                       // Do eight times.
            if ((int) (crc ^ byte) < 0)
                crc = (crc << 1) ^ 0x04C11DB7;
            else
                crc = crc << 1;
            byte = byte << 1;   // Ready next msg bit.
        }
        i = i + 1;
    }
    return Reverse(~crc);
}

/*
 *----------------------------------------------------------------------
 *
 * FUNCTION HashIpData --
 *
 *      Compute a hash from three values for an IP session
 *	(protocol, lower 2 bytes srcIP, lower 2 bytes dstIP)
 *
 *	This does not uniquely define a flow, since the source and
 *	destination ports are not used.  However, it will allow for
 *	identifying packets that are not related to a given flow.
 *
 * Returns:
 *      unsigned short hash
 *
 *----------------------------------------------------------------------
 */

unsigned short HashIpData(u_int8_t protocol, unsigned short sip, unsigned short dip)
{
    unsigned short p;

    p = (unsigned short) protocol;

    return p ^ sip ^ dip;
}

/*
 *----------------------------------------------------------------------
 *
 * FUNCTION  -- InitializeInterfaceFlowStatus
 *
 *      Sets all the interface values in the array to NOT_ACTIVE,
 *	indicating that no packets from this flow have been sent.
 *
 * Returns:
 *      unsigned short hash
 *
 *----------------------------------------------------------------------
 */

void InitializeInterfaceFlowStatus(Handler * h)
{
    int i;
    for (i = 0; i < 65535; i++)
    {
        h->flowsOutStateTable[i].iface = NOT_ACTIVE;
        h->flowsOutStateTable[i].otherHostSeen = 0;
        h->flowsOutStateTable[i].numPkts = 0;
    }
    return;
}
