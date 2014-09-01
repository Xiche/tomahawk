/*
 *  eventloop.h
 *
 *  Copyright (c) 2003 TippingPoint Technologies. All rights reserved.
 *
 * Please see LICENSE for licensing information
 *
 */


#ifndef _EVENTLOOP_
#define _EVENTLOOP_

#include "alloc.h"

typedef void (Callback)(void *userData);

typedef struct IdleCB {
    Callback *proc;
    void *userData;
    Callback *freeProc;
    struct IdleCB *next;
} IdleCB;

typedef struct TimerCB {
    Callback *proc;
    void *userData;
    Callback *freeProc;
    double startTime;
    int heapIndex;
} TimerCB;

typedef struct FileCB {
    Callback *proc;
    void *userData;
    Callback *freeProc;
    struct FileCB *next;
    int fd;
} FileCB;

typedef struct Peer {
    int ctrl;		   /* File descriptor for control socket */
    int cmdLen;            /* Length of next command to read */
    char cmdType;          /* 'x' = RPC, 'e' = error, 'd' = RDO, 'r' = return */
    int cmdId;             /* ID of the RPC request */
    int numRecv;           /* Number of bytes of the cmd we've received */
    char cmdBuffer[4096];
    char name[8];          /* Unique (shared) name for connection */
    FileCB *cb;
    struct Server *server;
    struct Peer *next;
} Peer;

typedef void (NewConnCallback)(Peer *p, void *userData);
typedef struct Server {
    int fd;
    struct sockaddr_in addr;
    NewConnCallback *newConnProc;
    void *newConnData;
    FileCB *cb;	        /* Really, this should be a list of callbacks so
                         * that we can support multiple clients... */
    Peer   *p;          /* linked list of peer connections */
} Server;

typedef int (Cmd)(void *userData, Peer *p, char *buffer, int len);

typedef struct CmdHandler {
    char prefix[32];
    Cmd *proc;
    void *userData;
    Callback *freeProc;
    struct CmdHandler *next;
} CmdHandler;

extern IdleCB *idleCallbacks;
extern TimerCB *timerHeap[];
extern FileCB *fileCallbacks;
extern CmdHandler *cmdHandlers;
extern unsigned long long int clicksPerUSec;

unsigned long long int Clicks(void);
void Calibrate(void);
double ReadSysClock(void);
IdleCB *CreateIdleCallback(Callback *proc, void *userData, Callback *freeProc);
void DeleteIdleCallback(IdleCB *cb);
void PrintHeap(char *str);
void UpHeap(int i1);
void DownHeap(int i1);
TimerCB *CreateTimerCallback(int milliseconds, Callback *proc, void *userData, Callback *freeProc);
void DeleteTimerCallback(TimerCB *t1);
FileCB *CreateFileCallback(int fd, Callback *proc, void *userData, Callback *freeProc);
void DeleteFileCallback(FileCB *cb);
int DoOneEvent(int block);
int HostToAddr(struct sockaddr_in *addr, char *host, int port);
void SendCmd(Peer *p, char *str);
void SendRDO(Peer *p, char *str);
void SendRPC(Peer *p, char *str);
void SendReturn(Peer *p, char *str);
void SendError(Peer *p, char *str);
Server *CreateServer(int myPort, NewConnCallback *proc, void *userData);
void DeleteServer(Server *s);
void CloseConnection(Peer *p);
CmdHandler *CreateCmdHandler(char *prefix, Cmd *proc, void *userData, Callback *freeProc);
void DeleteCmdHandler(CmdHandler *cb);
int ConnectToServer(Peer *p, char *hostname, int port);
void rlv_EventuallyFree (void *ptr);

#endif
