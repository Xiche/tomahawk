/*
 * eventloop.c
 *
 * Copyright (c) 2003, 2004 TippingPoint Technologies. All rights reserved.
 *
 * Please see LICENSE for licensing information
 */

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
#include <arpa/inet.h>

#include "eventloop.h"

IdleCB *idleCallbacks = NULL;
#define MAX_TIMERS	4096
TimerCB *timerHeap[MAX_TIMERS];
int numTimers = 0;
FileCB *fileCallbacks = NULL;
CmdHandler *cmdHandlers = NULL;
unsigned long long int clicksPerUSec;

extern int debugFlag;

/*
 *----------------------------------------------------------------------
 *
 * FUNCTION ReadSysClock --
 *
 *	Return the current value of the system clock as a double
 *
 *----------------------------------------------------------------------
 */

inline
unsigned long long int Clicks()
{
    unsigned long long int x;
    __asm__ volatile (".byte 0x0f, 0x31" : "=A" (x));
    return x;
}

void
Calibrate(void)
{
    unsigned long long int x1, x2;
    struct timeval start, end;

    x1 = Clicks();
    gettimeofday(&start, NULL);
    usleep(10000);
    x2 = Clicks();
    gettimeofday(&end, NULL);
    end.tv_sec -= start.tv_sec;
    end.tv_usec -= start.tv_usec;
    clicksPerUSec = (x2 - x1)/(end.tv_sec*1000000 + end.tv_usec);
}

double
ReadSysClock ()
{
    return Clicks() / clicksPerUSec / 1000000.0;
}

/*
 *----------------------------------------------------------------------
 *
 * FUNCTION CreateIdleCallback --
 *
 *	Create a timer callback function.   This function will
 *      get called from DoOneEvent() after the specfied amount
 *      of time.
 *
 * Returns:
 *	Handle to callback (used for delete)
 *
 * Side effects:
 *	The callback function will be invoked just before the
 *      next time the process voluntarily sleeps.
 *
 *----------------------------------------------------------------------
 */
IdleCB *
CreateIdleCallback (Callback *proc, void *userData, Callback *freeProc)
{
    IdleCB *new, *prev, *curr;

    new = (IdleCB *)calloc(sizeof(IdleCB), 1);
    new->proc = proc;
    new->userData = userData;
    new->freeProc = freeProc;

    /*
     * Find the tail of the idleCallbacks list
     */
    for (prev = NULL, curr = idleCallbacks;
         curr != NULL; prev = curr, curr = curr->next) {
    }

    if (prev == NULL) {
	idleCallbacks = new;
    } else {
	prev->next = new;
    }
    new->next = NULL;
    return new;
}

/*
 *----------------------------------------------------------------------
 *
 * FUNCTION DeleteIdleCallback --
 *
 *	Delete a previous created idle callback.
 *
 * Returns:
 *	None
 *
 * Side effects:
 *	The callback is cancelled
 *
 *----------------------------------------------------------------------
 */
void
DeleteIdleCallback (IdleCB *cb)
{
    IdleCB *prev, *curr;

    for (prev = NULL, curr = idleCallbacks;
         curr != NULL; prev = curr, curr = curr->next) {
        if (cb == curr) {
            break;
        }
    }
    if (curr == NULL) {
        return;
    }
    if (prev == NULL) {
	idleCallbacks = curr->next;
    } else {
	prev->next = curr->next;
    }
    if (cb->freeProc) {
        (*cb->freeProc)(cb->userData);
    }
    free (cb);
}

/*
 *----------------------------------------------------------------------
 *
 * FUNCTION PrintHeap --
 *
 *	Utility function to print the heap to stderr.
 *
 * Returns:
 *	None
 *
 * Side effects:
 *	None
 *
 *----------------------------------------------------------------------
 */
void
PrintHeap (char *str)
{
    TimerCB *t;
    int i;

    printf ("%s\n", str);
    for (i=0; i<numTimers; i++) {
	t = timerHeap[i];
	if (t == NULL) {
	    printf ("t[%04d]: NULL\n", i);
	} else {
	    printf ("t[%04d]: idx = %4d, time = %1.6f\n",
		    i, t->heapIndex, t->startTime);
	}
    }
}

#ifdef VALIDATE_HEAP
/*
 *----------------------------------------------------------------------
 *
 * FUNCTION ValidateHeap --
 *
 *	Utility function to validate the integrity of the timer heap.
 *
 * Returns:
 *	None
 *
 * Side effects:
 *	Exits on error
 *
 *----------------------------------------------------------------------
 */
int validateHeap = 1;
void
ValidateHeap (void)
{
    TimerCB *t1, *t2;
    int i2, i1;

    if (!validateHeap) {
        return;
    }
    for (i2=0; i2<numTimers; i2++) {
	t2 = timerHeap[i2];
	if (t2 == NULL || t2->heapIndex != i2) {
	    printf ("timer heap index corruption at index %d\n", i2);
	    PrintHeap("Error in Heap");
	    exit(1);
	}
	if (i2 != 0) {
	    i1 = (i2-1)/2;
	    t1 = timerHeap[i1];
	    if (t1->startTime >= t2->startTime) {
		printf ("timer heap order corruption at index %d\n", i2);
		PrintHeap("Error in Heap");
		exit(1);
	    }
	}
    }
}
#endif

/*
 *----------------------------------------------------------------------
 *
 * FUNCTION UpHeap --
 *
 *	Utility function to maintain the heap of timers.  This
 *	function moves the out of order element i1 up the heap
 *	until the heap is back in order.
 *
 * Returns:
 *	None
 *
 * Side effects:
 *	Heap is resorted
 *
 *----------------------------------------------------------------------
 */
void
UpHeap (int i1)
{
    int i2;
    TimerCB *t1, *t2;

    t1 = timerHeap[i1];
    while (i1 > 0) {
        i2 = (i1-1)/2;
	t2 = timerHeap[i2];
	if (t2->startTime < t1->startTime) {
	    break;
	}
	timerHeap[i1] = t2;
	t2->heapIndex = i1;
	timerHeap[i2] = t1;
	t1->heapIndex = i2;
	i1 = i2;
    }
#ifdef VALIDATE_HEAP
    ValidateHeap();
#endif
}

/*
 *----------------------------------------------------------------------
 *
 * FUNCTION DownHeap --
 *
 *	Utility function to maintain the heap of timers.  This
 *	function moves the out of order element i1 down the heap
 *	until the heap is back in order.
 *
 * Returns:
 *	None
 *
 * Side effects:
 *	Heap is resorted
 *
 *----------------------------------------------------------------------
 */
void
DownHeap (int i1)
{
    int i2;
    TimerCB *t1, *t2, *t3;

    t1 = timerHeap[i1];
    while (1) {
        i2 = (i1*2)+1;
	if (i2 >= numTimers) {
	    break;
	}
	t2 = timerHeap[i2];
	if (i2 == numTimers-1) {
	    t3 = t2;
	} else {
	    t3 = timerHeap[i2+1];
	}

	/*
	 * Set it up so that t2 is the timewise minimum
	 * of the two children of t1
	 */
	if (t2->startTime > t3->startTime) {
	    t2 = t3;
	}
	if (t1->startTime < t2->startTime) {
	    /*
	     * We're in order!
	     */
	    break;
	}
	i2 = t2->heapIndex;
	timerHeap[i1] = t2;
	t2->heapIndex = i1;
	timerHeap[i2] = t1;
	t1->heapIndex = i2;
	i1 = i2;
    }
#ifdef VALIDATE_HEAP
    ValidateHeap();
#endif
}

/*
 *----------------------------------------------------------------------
 *
 * FUNCTION CreateTimerCallback --
 *
 *	Create a timer callback function.   This function will
 *      get called from DoOneEvent() after the specfied amount
 *      of time.
 *
 * Returns:
 *	Handle to callback (used for delete)
 *
 * Side effects:
 *	Unless the callback is deleted, the
 *
 *----------------------------------------------------------------------
 */
TimerCB *
CreateTimerCallback (int milliseconds, Callback *proc, void *userData,
        Callback *freeProc)
{
    TimerCB *new;

    new = (TimerCB *)calloc(sizeof(TimerCB), 1);
    new->startTime = ReadSysClock() + milliseconds/1000.0;
    new->proc = proc;
    new->userData = userData;
    new->freeProc = freeProc;

    /*
     * Sanity check...
     */
    if (numTimers > MAX_TIMERS) {
        fprintf (stderr, "Ran out of space for timers.  Recompile"
	                 "with larger value of MAX_TIMERS\n");
	exit(1);
    }

    new->heapIndex = numTimers;
    timerHeap[numTimers] = new;
    numTimers++;
    UpHeap (numTimers-1);
    return new;
}

/*
 *----------------------------------------------------------------------
 *
 * FUNCTION DeleteTimerCallback --
 *
 *	Delete a previous created timer callback.
 *
 * Returns:
 *	None
 *
 * Side effects:
 *	The callback is cancelled, and the timerHeap is resource
 *
 *----------------------------------------------------------------------
 */
void
DeleteTimerCallback (TimerCB *t1)
{
    TimerCB *t2;
    int i2;

    if (t1 == NULL) {
        return;
    }
    numTimers--;
    if (numTimers > 0) {
	t2 = timerHeap[numTimers];
	i2 = t1->heapIndex;
	timerHeap[i2] = t2;
	t2->heapIndex = i2;
#ifdef VALIDATE_HEAP
	validateHeap = 0;
	DownHeap(i2);
	validateHeap = 1;
	UpHeap(t2->heapIndex);
#else
	DownHeap(i2);
	UpHeap(t2->heapIndex);
#endif
    }
    timerHeap[numTimers] = NULL;

    if (t1->freeProc) {
        (*t1->freeProc)(t1->userData);
    }
    free (t1);
}

/*
 *----------------------------------------------------------------------
 *
 * FUNCTION CreateFileCallback --
 *
 *	Create a callback function for a file or socket.
 *      The specified function will be invoked when the
 *      file or socket becomes readable.
 *
 * Returns:
 *	None
 *
 * Side effects:
 *	The callback will be invoked when the specified file
 *      descriptor becomes readable.
 *
 *----------------------------------------------------------------------
 */
FileCB *
CreateFileCallback (int fd, Callback *proc, void *userData,
        Callback *freeProc)
{
    FileCB *new;

    new = (FileCB *)calloc(sizeof(FileCB), 1);
    new->fd = fd;
    new->proc = proc;
    new->userData = userData;
    new->freeProc = freeProc;
    new->next = fileCallbacks;
    fileCallbacks = new;
    return new;
}

/*
 *----------------------------------------------------------------------
 *
 * FUNCTION DeleteFileCallback --
 *
 *	Delete a previously created file callback.
 *
 * Returns:
 *	None
 *
 * Side effects:
 *	The callback is cancelled
 *
 *----------------------------------------------------------------------
 */
void
DeleteFileCallback (FileCB *cb)
{
    FileCB *prev, *curr;

    for (prev = NULL, curr = fileCallbacks;
         curr != NULL; prev = curr, curr = curr->next) {
        if (cb == curr) {
            break;
        }
    }
    if (curr == NULL) {
        return;
    }
    if (prev == NULL) {
	fileCallbacks = curr->next;
    } else {
	prev->next = curr->next;
    }
    if (cb->freeProc) {
        (*cb->freeProc)(cb->userData);
    }
    free (cb);
}

/*
 *----------------------------------------------------------------------
 *
 * FUNCTION DoOneEvent --
 *
 *	Process one event and return.  An event is either
 *      an idle callback, a timer callback, or a file callback.
 *      If no event is ready, the process will block until
 *      one is ready.
 *
 * Returns:
 *	1 if an event was processed, 0 otherwise.
 *
 * Side effects:
 *	If a timer or idle callback is invoked, that callback
 *      is removed from the appropriate list.
 *
 *----------------------------------------------------------------------
 */
int
DoOneEvent(int block)        /* (IN) Should we block waiting on an event? */
{
    static int numFds = 0;
    int maxFd;
    static fd_set tmpFds, readFds;
    TimerCB *tcb;
    FileCB *fcb;
    IdleCB *icb;
    struct timeval timeout;
    struct timeval zeroTimeout;
    struct timeval *timePtr;

start:
    /*
     * If there are any fds ready from the previous call to select(),
     * process them now.  This prevents starvation.
     */
    if (numFds > 0) {
	for (fcb=fileCallbacks; fcb != NULL; fcb=fcb->next) {
	    if (FD_ISSET(fcb->fd, &readFds)) {
	        FD_CLR(fcb->fd, &readFds);
		numFds--;
	        if (debugFlag > 2) printf ("F\n");
		(*fcb->proc)(fcb->userData);
		return 1;
	    }
	}
    }

    /*
     * Handle any timers, and compute the timeout
     */
    if (numTimers != 0) {
	double dt;
	dt = timerHeap[0]->startTime - ReadSysClock();
	if (dt < 0) {
	    if (debugFlag > 2) printf ("T\n");
	    tcb = timerHeap[0];
	    (*tcb->proc)(tcb->userData);
	    DeleteTimerCallback (tcb);
	    return 1;
	}
	timeout.tv_sec = (int)dt;
	timeout.tv_usec = 1000000.0*(dt-timeout.tv_sec);
        timePtr = &timeout;
    } else {
        timePtr = NULL;
    }

    /*
     * Create the select mask
     */
    FD_ZERO(&readFds);
    maxFd = 0;
    for (fcb=fileCallbacks; fcb != NULL; fcb=fcb->next) {
        FD_SET(fcb->fd, &readFds);
	if (fcb->fd > maxFd) {
	    maxFd = fcb->fd;
	}
    }

    /*
     * Call select() once, with a 0 timeout, to see if any
     * file descriptors have become ready.  If so, start over.
     */
    zeroTimeout.tv_sec = 0;
    zeroTimeout.tv_usec = 0;
    memcpy (&tmpFds, &readFds, sizeof(tmpFds));
    numFds = select(maxFd+1, &readFds, NULL, NULL, &zeroTimeout);
    if (numFds > 0) {
        goto start;
    }
    if ((numFds < 0) && (errno != EINTR)) {
        perror ("select: ");
    }
    memcpy (&readFds, &tmpFds, sizeof(readFds));

    /*
     * Ok, we're going to block.  Process an idle handler if there
     * are any.
     */
    if (idleCallbacks != NULL) {
	if (debugFlag > 2) printf ("I\n");
	icb = idleCallbacks;
	(*icb->proc)(icb->userData);
	DeleteIdleCallback(icb);
        return 1;
    }

    /*
     * Call select().  Once select() returns,
     * go back to the top of the function.  We'll call the
     * callback function on our second time through
     */
    if (!block) {
        return 0;
    }
    if (debugFlag > 2) printf ("B\n");
    numFds = select(maxFd+1, &readFds, NULL, NULL, timePtr);
    goto start;
}

/*
 *----------------------------------------------------------------------
 *
 * FUNCTION HostToAddr --
 *
 *	Convert a hostname and port into a sockaddr.
 *
 * Returns:
 *	1 on success, 0 on failure
 *
 * Side effects:
 *	Exits on error.
 *
 *----------------------------------------------------------------------
 */

int
HostToAddr (
    struct sockaddr_in *addr,        /* (OUT) Parsed address */
    char *host,                      /* (IN) Hostname */
    int port)                        /* (IN) port */
{
    struct hostent *hostent;
    struct hostent _hostent;
    int hostaddr;
    int hostaddrPtr[2];

    hostent = gethostbyname(host);
    if (hostent == NULL) {
        hostaddr = inet_addr(host);
        if (hostaddr == -1) {
            return 0;
        }
        _hostent.h_addr_list    = (char **) hostaddrPtr;
        _hostent.h_addr_list[0] = (char *) &hostaddr;
        _hostent.h_addr_list[1] = NULL;
        _hostent.h_length = sizeof(hostaddr);
        _hostent.h_addrtype = AF_INET;
        hostent = &_hostent;
    }

    bzero((char *) addr, sizeof(struct sockaddr_in));
    addr->sin_family = AF_INET;

    memcpy((char *) &(addr->sin_addr.s_addr),
           (char *) hostent->h_addr_list[0],
           (size_t) hostent->h_length);
    addr->sin_port = htons(port);
    return 1;
}

/*
 *----------------------------------------------------------------------
 *
 * FUNCTION SendCmd --
 *
 *	Send a command on the control channel.
 *
 * Returns:
 *	None
 *
 * Side effects:
 *
 *----------------------------------------------------------------------
 */

static int cmdId = 1;

void
SendQualifiedCmd (Peer *p, int id, char type, char *str)
{
    int len = strlen(str);
    char cmdHdr[32];

    sprintf(cmdHdr, "%6d %c %6d ", len+16, type, id);
    write (p->ctrl, cmdHdr, strlen(cmdHdr));
    write (p->ctrl, str, len);
    if (debugFlag) {
        printf ("sent '%s%s' to peer\n", cmdHdr, str);
    }
}

void
SendCmd (Peer *p, char *str)
{
    SendQualifiedCmd(p, cmdId++, 'd', str);
}

void
SendRDO (Peer *p, char *str)
{
    SendQualifiedCmd(p, cmdId++, 'd', str);
}

void
SendRPC (Peer *p, char *str)
{
    SendQualifiedCmd(p, cmdId++, 'x', str);
}

void
SendReturn (Peer *p, char *str)
{
    SendQualifiedCmd(p, p->cmdId, 'r', str);
}

void
SendError (Peer *p, char *str)
{
    SendQualifiedCmd(p, p->cmdId, 'e', str);
}

/*
 *----------------------------------------------------------------------
 *
 * FUNCTION ProcessCmd --
 *
 *	Process a command received on the control channel.
 *
 * Returns:
 *	None
 *
 * Side effects:
 *	All handlers matching the command will be invoked, up
 *      to the first handler that verifies that it processed
 *      the command.
 *
 *      If no command handler is found, this function searches
 *      for the "unknow" command handler. For this feature to
 *      work, the "unknown" command handler must have been
 *      registered with CreateCmdHandler("unknown", ...)
 *
 *----------------------------------------------------------------------
 */

static void
ProcessCmd (Peer *p, char *buffer, int len)
{
    CmdHandler *ch;

    if (debugFlag) {
        printf ("processing command '%s' from peer\n", buffer);
    }
    for (ch = cmdHandlers; ch != NULL; ch = ch->next) {
        if (strncmp(ch->prefix, buffer, strlen(ch->prefix)) == 0) {
            if ((*ch->proc)(ch->userData, p, buffer, len)) {
                return;
            }
        }
    }
    ProcessCmd (p, "unknown", strlen("unknown"));
}

/*
 *----------------------------------------------------------------------
 *
 * FUNCTION RecvCmd --
 *
 *	Receive a command on the control channel.
 *
 * Returns:
 *	None
 *
 * Side effects:
 *
 *----------------------------------------------------------------------
 */

static void
RecvCmd (void *data)
{
    Peer *p = (Peer *)data;
    int numRead;
    char *endPtr;

    if (p->cmdLen != 0) {
	/*
	 * We're in the middle of reading a command.  Grab as much
	 * as is available.  If we get the whole thing, then process
	 * it and return.
	 */
	numRead = read (p->ctrl, p->cmdBuffer + p->numRecv,
	          p->cmdLen - p->numRecv);
        if (numRead == 0) {
            CloseConnection (p);
            return;
        }
        if (numRead == -1) {
            perror ("Error on control socket: ");
            exit(1);
        }
        p->numRecv += numRead;
        if (p->numRecv != p->cmdLen) {
            return;
        }
	p->cmdBuffer[p->cmdLen] = 0;
        ProcessCmd (p, p->cmdBuffer, p->cmdLen);
        memset (p->cmdBuffer, 0, p->cmdLen);
        p->cmdLen = 0;
        p->numRecv = 0;
        return;
    }

    /*
     * We're in the middle of reading the command header.
     */
    numRead = read (p->ctrl, p->cmdBuffer + p->numRecv, 16 - p->numRecv);
    if (numRead == 0) {
	CloseConnection (p);
	return;
    }
    p->numRecv += numRead;
    if (p->numRecv != 16) {
	return;
    }

    /*
     * Got the full header; parse it.
     */
    endPtr = p->cmdBuffer;
    while (*endPtr == ' ') {
        endPtr++;
    }
    assert (endPtr - p->cmdBuffer < 6);
    p->cmdLen = strtoul(endPtr, &endPtr, 10) - 16;
    assert (endPtr-p->cmdBuffer == 6);
    assert (*endPtr == ' ');
    p->cmdType = p->cmdBuffer[7];
    assert (p->cmdType == 'x' || p->cmdType == 'd' ||
	    p->cmdType == 'e' || p->cmdType == 'r');
    endPtr += 2;
    assert (*endPtr == ' ');
    while (*endPtr == ' ') {
        endPtr++;
    }
    assert (endPtr - p->cmdBuffer < 15);
    p->cmdId = strtoul(endPtr, &endPtr, 10);
    assert (endPtr-p->cmdBuffer == 15);
    assert (*endPtr == ' ');
    p->numRecv = 0;
}

static void
AcceptConnection (void *data)
{
    Server *server = (Server *)data;
    int value;
    socklen_t len;
    Peer *rv;
    struct sockaddr_in addr;

    rv = (Peer *)calloc(sizeof(Peer), 1);
    len = sizeof(addr);
    rv->ctrl = accept(server->fd, (struct sockaddr *)&addr, &len);
    if (rv->ctrl < 0) {
	fprintf (stderr, "couldn't accept from socket: %s", strerror(errno));
	exit(1);
    }
    value = 1;
    setsockopt(rv->ctrl, SOL_SOCKET, SO_REUSEADDR, (char *)&value, sizeof(value));
    rv->cb = CreateFileCallback (rv->ctrl, RecvCmd, rv, NULL);
    if (server->newConnProc) {
	(*server->newConnProc)(rv, server->newConnData);
    }
    rv->server = server;
    rv->next = server->p;
    server->p = rv;
}

Server *
CreateServer (int myPort, NewConnCallback *proc, void *userData)
{
    int status, sock;
    Server *rv;
    int value;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
#ifdef EXIT_ON_ERROR
	goto error;
#else
        return NULL;
#endif
    }

    rv = (Server *)calloc(sizeof(Server), 1);
    rv->fd = sock;
    rv->addr.sin_family = AF_INET;
    rv->addr.sin_addr.s_addr = INADDR_ANY;
    rv->addr.sin_port = htons((unsigned short)myPort);

    status = bind(sock, (struct sockaddr *) &rv->addr, sizeof(rv->addr));
    if (status >= 0) {
	status = listen(sock, 5);
    }
    if (status < 0) {
#ifdef EXIT_ON_ERROR
	goto error;
#else
        value = errno;
        free( rv );
        close( sock );
        errno = value;
        return NULL;
#endif
    }
    value = 1;
    setsockopt(rv->fd, SOL_SOCKET, SO_REUSEADDR, (char *)&value, sizeof(value));
    rv->newConnProc = proc;
    rv->newConnData = userData;
    rv->cb = CreateFileCallback (rv->fd, AcceptConnection, rv, NULL);
    return rv;

#ifdef EXIT_ON_ERROR
error:
    fprintf (stderr, "error opening socket: %s\n", strerror(errno));
    exit(1);
#endif
}

void
DeleteServer(Server *s)
{
    Peer  *p;

    while (s->p) {
        p = s->p;
        s->p = p->next;
        CloseConnection (p);
    }
    DeleteFileCallback (s->cb);
    close (s->fd);
    free (s);
}

void
CloseConnection (Peer *p)
{
    Peer *prev, *curr;

    /*
     * Unlink from server's link list
     */
    if (p->server != NULL) {
	for (prev = NULL, curr = p->server->p; curr != NULL;
	     prev = curr, curr = curr->next) {
	    if (curr == p) {
		if (prev != NULL) {
		    prev->next = curr->next;
		} else {
		    p->server->p = curr->next;
		}
	    }
	}
    }
    DeleteFileCallback (p->cb);
    close (p->ctrl);
    free (p);
}

/*
 *----------------------------------------------------------------------
 *
 * FUNCTION CreateCmdHandler --
 *
 *	Create a command handler.  This arranges for a function
 *      (proc) to be invoked whenever a command is received that
 *      matches the specified prefix.  This proc should return
 *      1 if it processed the command (preventing other cmd handlers
 *      from being called), 0 otherwise.
 *
 * Returns:
 *	Handle to cmdHandler (used for delete)
 *
 * Side effects:
 *	The callback function will be invoked when a command matching
 *      the specified prefix arrives on a control channel.
 *
 *----------------------------------------------------------------------
 */
CmdHandler *
CreateCmdHandler (char *prefix, Cmd *proc, void *userData, Callback *freeProc)
{
    CmdHandler *new;

    new = (CmdHandler *)calloc(sizeof(CmdHandler), 1);
    if (prefix == NULL) {
        prefix = "";
    }
    strncpy (new->prefix, prefix, sizeof(new->prefix));
    new->proc = proc;
    new->userData = userData;
    new->freeProc = freeProc;
    new->next = cmdHandlers;
    cmdHandlers = new;
    return new;
}

/*
 *----------------------------------------------------------------------
 *
 * FUNCTION DeleteCmdHandler --
 *
 *	Delete a previous created idle callback.
 *
 * Returns:
 *	None
 *
 * Side effects:
 *	The callback is cancelled
 *
 *----------------------------------------------------------------------
 */
void
DeleteCmdHandler (CmdHandler *cb)
{
    CmdHandler *prev, *curr;

    for (prev = NULL, curr = cmdHandlers;
         curr != NULL; prev = curr, curr = curr->next) {
        if (cb == curr) {
            break;
        }
    }
    if (curr == NULL) {
        return;
    }
    if (prev == NULL) {
	cmdHandlers = curr->next;
    } else {
	prev->next = curr->next;
    }
    if (cb->freeProc) {
        (*cb->freeProc)(cb->userData);
    }
    free (cb);
}

int
ConnectToServer(Peer *p, char *hostname, int port)
{
    struct sockaddr_in addr;
    struct protoent *pp;

    if (!HostToAddr (&addr, hostname, port)) {
        fprintf (stderr, "Couldn't find host %s\n", hostname);
	return 0;
    }
    pp = getprotobyname ("tcp");

    p->ctrl = socket (AF_INET, SOCK_STREAM, pp->p_proto);
    if (p->ctrl < 0) {
        perror ("Error creating socket: ");
	return 0;
    }
    if (connect (p->ctrl, (struct sockaddr *) &addr, sizeof (addr)) < 0) {
        fprintf (stderr, "Error connecting to host %s: %s", hostname,
		strerror(errno));
	return 0;
    }
    p->cb = CreateFileCallback (p->ctrl, RecvCmd, p, NULL);
    p->cmdLen = p->numRecv = 0;
    return 1;
}

