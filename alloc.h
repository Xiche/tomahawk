/* 
 * alloc.h --
 *
 *    Interface to malloc and free that provides support for debugging problems
 *    involving overwritten, double freeing memory and loss of memory.
 *
 * Copyright (c) 1991-1994 The Regents of the University of California.
 * Copyright (c) 1994-1997 Sun Microsystems, Inc.
 * Copyright (c) 1998-1999 by Scriptics Corporation.
 *
 * This code contributed by Karl Lehenbauer and Mark Diekhans
 *
 * See the file "alloc.c" for information on usage and redistribution
 * of this file, and for a DISCLAIMER OF ALL WARRANTIES.
 * 
 */

#ifndef __ALLOC_H
#define __ALLOC_H
#ifdef MEM_DEBUG

#   define malloc(x) DbCkalloc(x, __FILE__, __LINE__)
#   define calloc(x,y) DbCkalloc((x)*(y), __FILE__, __LINE__)
#   define free(x)  DbCkfree(x, __FILE__, __LINE__)
#   define realloc(x,y) DbCkrealloc((x), (y),__FILE__, __LINE__)
#   define VALIDATE()	ValidateAllMemory (__FILE__, __LINE__)
#endif

typedef void (FreeProc)(void *userData);

extern int validate_memory;
extern int alloc_tracing;

void DumpMemoryInfo(FILE *outFile);
void ValidateAllMemory (char *file, int line);
int DumpActiveMemory (char *fileName);

void *DbCkalloc(unsigned int size, char *file, int line);
int DbCkfree(void *ptr, char *file, int   line);
void *DbCkrealloc(void *ptr, unsigned int size, char *file, int line);

void Preserve(void *clientData);
void Release(void *clientData);
void EventuallyFree(void *clientData, FreeProc *freeProc);
#endif
