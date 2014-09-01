/* 
 * alloc.c --
 *
 *    Interface to malloc and free that provides support for debugging problems
 *    involving overwritten, double freeing memory and loss of memory.
 *    Includes a collection of procedures that are used
 *    to make sure that data structures aren't reallocated when
 *    there are nested functions or structures that depend on
 *    their existence.
 *
 * Copyright (c) 1991-1994 The Regents of the University of California.
 * Copyright (c) 1994-1997 Sun Microsystems, Inc.
 * Copyright (c) 1998-1999 by Scriptics Corporation.
 *
 * This code contributed by Karl Lehenbauer and Mark Diekhans
 *
 * This software is copyrighted by the Regents of the University of
 * California, Sun Microsystems, Inc., Scriptics Corporation, ActiveState
 * Corporation and other parties.  The following terms apply to all files
 * associated with the software unless explicitly disclaimed in
 * individual files.
 * 
 * The authors hereby grant permission to use, copy, modify, distribute,
 * and license this software and its documentation for any purpose, provided
 * that existing copyright notices are retained in all copies and that this
 * notice is included verbatim in any distributions. No written agreement,
 * license, or royalty fee is required for any of the authorized uses.
 * Modifications to this software may be copyrighted by their authors
 * and need not follow the licensing terms described here, provided that
 * the new terms are clearly indicated on the first page of each file where
 * they apply.
 * 
 * IN NO EVENT SHALL THE AUTHORS OR DISTRIBUTORS BE LIABLE TO ANY PARTY
 * FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING OUT OF THE USE OF THIS SOFTWARE, ITS DOCUMENTATION, OR ANY
 * DERIVATIVES THEREOF, EVEN IF THE AUTHORS HAVE BEEN ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 * 
 * THE AUTHORS AND DISTRIBUTORS SPECIFICALLY DISCLAIM ANY WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT.  THIS SOFTWARE
 * IS PROVIDED ON AN "AS IS" BASIS, AND THE AUTHORS AND DISTRIBUTORS HAVE
 * NO OBLIGATION TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
 * MODIFICATIONS.
 * 
 * GOVERNMENT USE: If you are acquiring this software on behalf of the
 * U.S. government, the Government shall have only "Restricted Rights"
 * in the software and related documentation as defined in the Federal 
 * Acquisition Regulations (FARs) in Clause 52.227.19 (c) (2).  If you
 * are acquiring the software on behalf of the Department of Defense, the
 * software shall be classified as "Commercial Computer Software" and the
 * Government shall have only "Restricted Rights" as defined in Clause
 * 252.227-7013 (c) (1) of DFARs.  Notwithstanding the foregoing, the
 * authors grant the U.S. Government and others acting in its behalf
 * permission to use and distribute the software in accordance with the
 * terms specified in this license. 
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>

#include <sys/time.h>
#include <sys/resource.h>
#include <time.h>

#undef calloc
#undef free
#undef malloc
#undef realloc

#define FALSE	0
#define TRUE	1
#define UCHAR(c) ((unsigned char) (c))
#ifdef MEM_DEBUG
#  define FREE(x)		DbCkfree((x), __FILE__, __LINE__)
#else
#  define FREE(x)		free(x)
#endif


extern int debugFlag;

typedef void (FreeProc)(void *userData);


/*
 * One of the following structures is allocated each time the
 * "memory tag" command is invoked, to hold the current tag.
 */

typedef struct MemTag {
    int refCount;		/* Number of mem_headers referencing
				 * this tag. */
    char string[4];		/* Actual size of string will be as
				 * large as needed for actual tag.  This
				 * must be the last field in the structure. */
} MemTag;

#define TAG_SIZE(bytesInString) ((unsigned) sizeof(MemTag) + bytesInString - 3)

static MemTag *curTagPtr = NULL;/* Tag to use in all future mem_headers
				 * (set by "memory tag" command). */

/*
 * One of the following structures is allocated just before each
 * dynamically allocated chunk of memory, both to record information
 * about the chunk and to help detect chunk under-runs.
 */

#define LOW_GUARD_SIZE (8 + (32 - (sizeof(long) + sizeof(int)))%8)
struct mem_header {
    struct mem_header *flink;
    struct mem_header *blink;
    MemTag *tagPtr;		/* Tag from "memory tag" command;  may be
				 * NULL. */
    char *file;
    long length;
    int line;
    unsigned char low_guard[LOW_GUARD_SIZE];
				/* Aligns body on 8-byte boundary, plus
				 * provides at least 8 additional guard bytes
				 * to detect underruns. */
    char body[1];		/* First byte of client's space.  Actual
				 * size of this field will be larger than
				 * one. */
};

/*
 * The following data structure is used to keep track of all the
 * Preserve calls that are still in effect.  It grows as needed
 * to accommodate any number of calls in effect.
 */

typedef struct {
    void *clientData;	/* Address of preserved block. */
    int refCount;	/* Number of Preserve calls in effect
			 * for block. */
    int mustFree;	/* Non-zero means EventuallyFree was
			 * called while a Preserve call was in
			 * effect, so the structure must be freed
			 * when refCount becomes zero. */
    FreeProc *freeProc;	/* Procedure to call to free. */
} Reference;

static Reference *refArray;	/* First in array of references. */
static int spaceAvl = 0;	/* Total number of structures available
				 * at *firstRefPtr. */
static int inUse = 0;		/* Count of structures currently in use
				 * in refArray. */
#define INITIAL_SIZE 2

/*
 * The following data structure is used to keep track of whether an
 * arbitrary block of memory has been deleted.  This is used by the
 * TclHandle code to avoid the more time-expensive algorithm of
 * Preserve().  This mechanism is mainly used when we have lots of
 * references to a few big, expensive objects that we don't want to live
 * any longer than necessary.
 */

typedef struct HandleStruct {
    void *ptr;			/* Pointer to the memory block being
				 * tracked.  This field will become NULL when
				 * the memory block is deleted.  This field
				 * must be the first in the structure. */
#ifdef MEM_DEBUG
    void *ptr2;			/* Backup copy of the abpve pointer used to
				 * ensure that the contents of the handle are
				 * not changed by anyone else. */
#endif
    int refCount;		/* Number of TclHandlePreserve() calls in
				 * effect on this handle. */
} HandleStruct;



static struct mem_header *allocHead = NULL;  /* List of allocated structures */

#define GUARD_VALUE  0141

/*
 * The following macro determines the amount of guard space *above* each
 * chunk of memory.
 */

#define HIGH_GUARD_SIZE 8

/*
 * The following macro computes the offset of the "body" field within
 * mem_header.  It is used to get back to the header pointer from the
 * body pointer that's used by clients.
 */

#define BODY_OFFSET \
	((unsigned long) (&((struct mem_header *) 0)->body))

static int total_mallocs = 0;
static int total_frees = 0;
static int current_bytes_malloced = 0;
static int maximum_bytes_malloced = 0;
static int current_malloc_packets = 0;
static int maximum_malloc_packets = 0;
static int break_on_malloc = 0;
static int trace_on_at_malloc = 0;
#ifdef ALLOC_TRACING
    int  alloc_tracing = TRUE;
#else
    int  alloc_tracing = FALSE;
#endif
static int  init_malloced_bodies = TRUE;
#ifdef MEM_VALIDATE
    int  validate_memory = TRUE;
#else
    int  validate_memory = FALSE;
#endif

/*
 * Prototypes for procedures defined in this file:
 */

static void		ValidateMemory (struct mem_header *memHeaderP,
			    char *file, int line, int nukeGuards);

/*
 *----------------------------------------------------------------------
 *
 * DumpMemoryInfo --
 *     Display the global memory management statistics.
 *
 *----------------------------------------------------------------------
 */
void
DumpMemoryInfo(outFile) 
    FILE *outFile;
{
    fprintf(outFile,"total mallocs             %10d\n", 
	    total_mallocs);
    fprintf(outFile,"total frees               %10d\n", 
	    total_frees);
    fprintf(outFile,"current packets allocated %10d\n", 
	    current_malloc_packets);
    fprintf(outFile,"current bytes allocated   %10d\n", 
	    current_bytes_malloced);
    fprintf(outFile,"maximum packets allocated %10d\n", 
	    maximum_malloc_packets);
    fprintf(outFile,"maximum bytes allocated   %10d\n", 
	    maximum_bytes_malloced);
}

/*
 *----------------------------------------------------------------------
 *
 * ValidateMemory --
 *
 *	Validate memory guard zones for a particular chunk of allocated
 *	memory.
 *
 * Results:
 *	None.
 *
 * Side effects:
 *	Prints validation information about the allocated memory to stderr.
 *
 *----------------------------------------------------------------------
 */

static void
ValidateMemory(memHeaderP, file, line, nukeGuards)
    struct mem_header *memHeaderP;	/* Memory chunk to validate */
    char              *file;		/* File containing the call to
					 * ValidateAllMemory */
    int                line;		/* Line number of call to
					 * ValidateAllMemory */
    int                nukeGuards;	/* If non-zero, indicates that the
					 * memory guards are to be reset to 0
					 * after they have been printed */
{
    unsigned char *hiPtr;
    int   idx;
    int   guard_failed = FALSE;
    int byte;
    
    for (idx = 0; idx < LOW_GUARD_SIZE; idx++) {
        byte = *(memHeaderP->low_guard + idx);
        if (byte != GUARD_VALUE) {
            guard_failed = TRUE;
            fflush(stdout);
	    byte &= 0xff;
            fprintf(stderr, "low guard byte %d is 0x%x  \t%c\n", idx, byte,
		    (isprint(UCHAR(byte)) ? byte : ' ')); /* INTL: bytes */
        }
    }
    if (guard_failed) {
        DumpMemoryInfo (stderr);
        fprintf(stderr, "low guard failed at %lx, %s %d\n",
                 (long unsigned int) memHeaderP->body, file, line);
        fflush(stderr);  /* In case name pointer is bad. */
        fprintf(stderr, "%ld bytes allocated at (%s %d)\n", memHeaderP->length,
		memHeaderP->file, memHeaderP->line);
        fprintf(stderr, "Memory validation failure");
        exit(1);
    }

    hiPtr = (unsigned char *)memHeaderP->body + memHeaderP->length;
    for (idx = 0; idx < HIGH_GUARD_SIZE; idx++) {
        byte = *(hiPtr + idx);
        if (byte != GUARD_VALUE) {
            guard_failed = TRUE;
            fflush (stdout);
	    byte &= 0xff;
            fprintf(stderr, "hi guard byte %d is 0x%x  \t%c\n", idx, byte,
		    (isprint(UCHAR(byte)) ? byte : ' ')); /* INTL: bytes */
        }
    }

    if (guard_failed) {
        DumpMemoryInfo (stderr);
        fprintf(stderr, "high guard failed at %lx, %s %d\n",
                 (long unsigned int) memHeaderP->body, file, line);
        fflush(stderr);  /* In case name pointer is bad. */
        fprintf(stderr, "%ld bytes allocated at (%s %d)\n",
		memHeaderP->length, memHeaderP->file,
		memHeaderP->line);
        fprintf(stderr, "Memory validation failure");
        exit(1);
    }

    if (nukeGuards) {
        memset ((char *) memHeaderP->low_guard, 0, LOW_GUARD_SIZE); 
        memset ((char *) hiPtr, 0, HIGH_GUARD_SIZE); 
    }
}

/*
 *----------------------------------------------------------------------
 *
 * ValidateAllMemory --
 *
 *	Validate memory guard regions for all allocated memory.
 *
 * Results:
 *	None.
 *
 * Side effects:
 *	Displays memory validation information to stderr.
 *
 *----------------------------------------------------------------------
 */

void
ValidateAllMemory (char *file, int line)
{
#ifdef MEM_DEBUG
    struct mem_header *memScanP;

    for (memScanP = allocHead; memScanP != NULL; memScanP = memScanP->flink) {
        ValidateMemory(memScanP, file, line, FALSE);
    }
#endif
}

/*
 *----------------------------------------------------------------------
 *
 * DumpActiveMemory --
 *
 *	Displays all allocated memory to a file; if no filename is given,
 *	information will be written to stderr.
 *
 * Results:
 *	Return 0 if an error accessing the file occures, `errno' 
 *	will have the file error number left in it.
 *----------------------------------------------------------------------
 */
int
DumpActiveMemory (fileName)
    char *fileName;		/* Name of the file to write info to */
{
#ifdef MEM_DEBUG
    FILE              *fileP;
    struct mem_header *memScanP;
    char              *address;

    if (fileName == NULL) {
	fileP = stderr;
    } else {
	fileP = fopen(fileName, "w");
	if (fileP == NULL) {
	    return 0;
	}
    }
    DumpMemoryInfo(fileP) ;

    for (memScanP = allocHead; memScanP != NULL; memScanP = memScanP->flink) {
        address = &memScanP->body [0];
        fprintf(fileP, "%8lx - %8lx  %7ld @ %s %d %s",
		(long unsigned int) address,
                 (long unsigned int) address + memScanP->length - 1,
		 memScanP->length, memScanP->file, memScanP->line,
		 (memScanP->tagPtr == NULL) ? "" : memScanP->tagPtr->string);
	(void) fputc('\n', fileP);
    }

    if (fileP != stderr) {
	fclose (fileP);
    }
#endif
    return 1;
}

/*
 *----------------------------------------------------------------------
 *
 * DbCkalloc - debugging malloc
 *
 *        Allocate the requested amount of space plus some extra for
 *        guard bands at both ends of the request, plus a size, panicing 
 *        if there isn't enough space, then write in the guard bands
 *        and return the address of the space in the middle that the
 *        user asked for.
 *
 *        The second and third arguments are file and line, these contain
 *        the filename and line number corresponding to the caller.
 *        These are sent by the malloc macro; it uses the preprocessor
 *        autodefines __FILE__ and __LINE__.
 *
 *----------------------------------------------------------------------
 */
void *
DbCkalloc(unsigned int size, char *file, int line)
{
    struct mem_header *result;

    if (validate_memory)
        ValidateAllMemory (file, line);

    result = (struct mem_header *) malloc((unsigned)size + 
                              sizeof(struct mem_header) + HIGH_GUARD_SIZE);
    if (result == NULL) {
        fflush(stdout);
        DumpMemoryInfo(stderr);
        fprintf(stderr, "unable to alloc %d bytes, %s line %d",
		 size, file, line);
	exit(1);
    }

    /*
     * Fill in guard zones and size.  Also initialize the contents of
     * the block with bogus bytes to detect uses of initialized data.
     * Link into allocated list.
     */
    if (init_malloced_bodies) {
        memset ((void *) result, GUARD_VALUE,
		size + sizeof(struct mem_header) + HIGH_GUARD_SIZE);
    } else {
	memset ((char *) result->low_guard, GUARD_VALUE, LOW_GUARD_SIZE);
	memset (result->body + size, GUARD_VALUE, HIGH_GUARD_SIZE);
    }
    result->length = size;
    result->tagPtr = curTagPtr;
    if (curTagPtr != NULL) {
	curTagPtr->refCount++;
    }
    result->file = file;
    result->line = line;
    result->flink = allocHead;
    result->blink = NULL;

    if (allocHead != NULL)
        allocHead->blink = result;
    allocHead = result;

    total_mallocs++;
    if (trace_on_at_malloc && (total_mallocs >= trace_on_at_malloc)) {
        (void) fflush(stdout);
        fprintf(stderr, "reached malloc trace enable point (%d)\n",
                total_mallocs);
        fflush(stderr);
        alloc_tracing = TRUE;
        trace_on_at_malloc = 0;
    }

    if (alloc_tracing)
        fprintf(stderr,"malloc %lx %d %s %d\n",
		(long unsigned int) result->body, size, file, line);

    if (break_on_malloc && (total_mallocs >= break_on_malloc)) {
        break_on_malloc = 0;
        (void) fflush(stdout);
        fprintf(stderr,"reached malloc break limit (%d)\n", 
                total_mallocs);
        fprintf(stderr, "program will now enter C debugger\n");
        (void) fflush(stderr);
	abort();
    }

    current_malloc_packets++;
    if (current_malloc_packets > maximum_malloc_packets)
        maximum_malloc_packets = current_malloc_packets;
    current_bytes_malloced += size;
    if (current_bytes_malloced > maximum_bytes_malloced)
        maximum_bytes_malloced = current_bytes_malloced;


    memset (result->body, 0, size);
    return result->body;
}

/*
 *----------------------------------------------------------------------
 *
 * DbCkfree - debugging free
 *
 *        Verify that the low and high guards are intact, and if so
 *        then free the buffer else panic.
 *
 *        The guards are erased after being checked to catch duplicate
 *        frees.
 *
 *        The second and third arguments are file and line, these contain
 *        the filename and line number corresponding to the caller.
 *        These are sent by the free macro; it uses the preprocessor
 *        autodefines __FILE__ and __LINE__.
 *
 *----------------------------------------------------------------------
 */

int
DbCkfree(void *ptr, char *file, int   line)
{
    struct mem_header *memp;

    if (ptr == NULL) {
	return 0;
    }

    /*
     * The following cast is *very* tricky.  Must convert the pointer
     * to an integer before doing arithmetic on it, because otherwise
     * the arithmetic will be done differently (and incorrectly) on
     * word-addressed machines such as Crays (will subtract only bytes,
     * even though BODY_OFFSET is in words on these machines).
     */

    memp = (struct mem_header *) (((unsigned long) ptr) - BODY_OFFSET);

    if (alloc_tracing) {
        fprintf(stderr, "free %lx %ld %s %d\n",
		(long unsigned int) memp->body, memp->length, file, line);
    }

    if (validate_memory) {
        ValidateAllMemory(file, line);
    }

    ValidateMemory(memp, file, line, TRUE);
    if (init_malloced_bodies) {
	memset((void *) ptr, GUARD_VALUE, (size_t) memp->length);
    }

    total_frees++;
    current_malloc_packets--;
    current_bytes_malloced -= memp->length;

    if (memp->tagPtr != NULL) {
	memp->tagPtr->refCount--;
	if ((memp->tagPtr->refCount == 0) && (curTagPtr != memp->tagPtr)) {
	    free((char *) memp->tagPtr);
	}
    }

    /*
     * Delink from allocated list
     */
    if (memp->flink != NULL)
        memp->flink->blink = memp->blink;
    if (memp->blink != NULL)
        memp->blink->flink = memp->flink;
    if (allocHead == memp)
        allocHead = memp->flink;
    free((char *) memp);

    return 0;
}

/*
 *--------------------------------------------------------------------
 *
 * DbCkrealloc - debugging ckrealloc
 *
 *	Reallocate a chunk of memory by allocating a new one of the
 *	right size, copying the old data to the new location, and then
 *	freeing the old memory space, using all the memory checking
 *	features of this package.
 *
 *--------------------------------------------------------------------
 */
void *
DbCkrealloc(void *ptr, unsigned int size, char *file, int line)
{
    void *new;
    unsigned int copySize;
    struct mem_header *memp;

    if (ptr == NULL) {
	return DbCkalloc(size, file, line);
    }

    /*
     * See comment from DbCkfree before you change the following
     * line.
     */

    memp = (struct mem_header *) (((unsigned long) ptr) - BODY_OFFSET);

    copySize = size;
    if (copySize > (unsigned int) memp->length) {
	copySize = memp->length;
    }
    new = DbCkalloc(size, file, line);
    memcpy((void *) new, ptr, (size_t) copySize);
    DbCkfree(ptr, file, line);
    return new;
}

/*
 *----------------------------------------------------------------------
 *
 * Preserve --
 *
 *	This procedure is used by a procedure to declare its interest
 *	in a particular block of memory, so that the block will not be
 *	reallocated until a matching call to Release has been made.
 *
 * Results:
 *	None.
 *
 * Side effects:
 *	Information is retained so that the block of memory will
 *	not be freed until at least the matching call to Release.
 *
 *----------------------------------------------------------------------
 */

void
Preserve(void *clientData)
{
    Reference *refPtr;
    int i;

    /*
     * See if there is already a reference for this pointer.  If so,
     * just increment its reference count.
     */

    for (i = 0, refPtr = refArray; i < inUse; i++, refPtr++) {
	if (refPtr->clientData == clientData) {
	    refPtr->refCount++;
	    return;
	}
    }

    /*
     * Make a reference array if it doesn't already exist, or make it
     * bigger if it is full.
     */

    if (inUse == spaceAvl) {
	if (spaceAvl == 0) {
	    refArray = (Reference *) malloc((unsigned)
		    (INITIAL_SIZE*sizeof(Reference)));
	    spaceAvl = INITIAL_SIZE;
	} else {
	    Reference *new;

	    new = (Reference *) malloc((unsigned)
		    (2*spaceAvl*sizeof(Reference)));
	    memcpy((void *) new, (void *) refArray,
                    spaceAvl*sizeof(Reference));
	    free((char *) refArray);
	    refArray = new;
	    spaceAvl *= 2;
	}
    }

    /*
     * Make a new entry for the new reference.
     */
    refPtr = &refArray[inUse];
    refPtr->clientData = clientData;
    refPtr->refCount = 1;
    refPtr->mustFree = 0;
    refPtr->freeProc = NULL;
    inUse += 1;
}

/*
 *----------------------------------------------------------------------
 *
 * Release --
 *
 *	This procedure is called to cancel a previous call to
 *	Preserve, thereby allowing a block of memory to be
 *	freed (if no one else cares about it).
 *
 * Results:
 *	None.
 *
 * Side effects:
 *	If EventuallyFree has been called for clientData, and if
 *	no other call to Preserve is still in effect, the block of
 *	memory is freed.
 *
 *----------------------------------------------------------------------
 */

void
Release(void *clientData)
{
    Reference *refPtr;
    int mustFree;
    FreeProc *freeProc;
    int i;

    for (i = 0, refPtr = refArray; i < inUse; i++, refPtr++) {
	if (refPtr->clientData != clientData) {
	    continue;
	}
	refPtr->refCount--;
	if (refPtr->refCount == 0) {

            /*
             * Must remove information from the slot before calling freeProc
             * to avoid reentrancy problems if the freeProc calls Preserve
             * on the same clientData. Copy down the last reference in the
             * array to overwrite the current slot.
             */

            freeProc = refPtr->freeProc;
            mustFree = refPtr->mustFree;
	    inUse--;
	    if (i < inUse) {
		refArray[i] = refArray[inUse];
	    }
	    if (mustFree) {
		if (freeProc == NULL) {
		    FREE(clientData);
		} else {
		    (*freeProc)((char *)clientData);
		}
		return;
	    }
	}
	return;
    }

    /*
     * Reference not found.  This is a bug in the caller.
     */

    fprintf(stderr, "Release couldn't find reference for 0x%lx\n",
    	   (long)clientData);
    abort();
}

/*
 *----------------------------------------------------------------------
 *
 * EventuallyFree --
 *
 *	Free up a block of memory, unless a call to Preserve is in
 *	effect for that block.  In this case, defer the free until all
 *	calls to Preserve have been undone by matching calls to
 *	Release.
 *
 * Results:
 *	None.
 *
 * Side effects:
 *	Ptr may be released by calling free().
 *
 *----------------------------------------------------------------------
 */

void
EventuallyFree(clientData, freeProc)
    void *clientData;	/* Pointer to malloc'ed block of memory. */
    FreeProc *freeProc;	/* Procedure to actually do free. */
{
    Reference *refPtr;
    int i;

    /*
     * See if there is a reference for this pointer.  If so, set its
     * "mustFree" flag (the flag had better not be set already!).
     */

    for (i = 0, refPtr = refArray; i < inUse; i++, refPtr++) {
	if (refPtr->clientData != clientData) {
	    continue;
	}
	if (refPtr->mustFree) {
	    fprintf (stderr, "EventuallyFree called twice for 0x%lx\n",
	    	     (long)clientData);
        }
        refPtr->mustFree = 1;
	refPtr->freeProc = freeProc;
        return;
    }

    /*
     * No reference for this block.  Free it now.
     */
    if (freeProc == NULL) {
	FREE(clientData);
    } else {
	(*freeProc)((char *)clientData);
    }
}
