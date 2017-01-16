/*
 * getpmap syscall test
 * 2016-2017 Tong Zhang<ztong@vt.edu>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>

#define _NR_SYS_GETPMAP (399)

struct pmap {
	unsigned long start_mpx;
	unsigned long end_mpx;
};

#define GETPMAP(x) \
	syscall(_NR_SYS_GETPMAP, x)

#define DUMP_PMAP(x) \
	printf("mpx:0x%lx-0x%lx\n",\
		(x)->start_mpx, \
		(x)->end_mpx)\

struct pmap pmap;

void benchmark()
{
	int i;
	for(i=0;i<100000;i++)
		GETPMAP(&pmap);
}

int main(int argc, char** argv)
{
#if 1
    memset((void*)&pmap, 0, sizeof(struct pmap));
	GETPMAP(&pmap);
	DUMP_PMAP(&pmap);
	void *p = malloc(100);
    memset((void*)&pmap, 0, sizeof(struct pmap));
	GETPMAP(&pmap);
	DUMP_PMAP(&pmap);
	free(p);
    memset((void*)&pmap, 0, sizeof(struct pmap));
	GETPMAP(&pmap);
	DUMP_PMAP(&pmap);
#else
	benchmark();
#endif
	return 0;
}

