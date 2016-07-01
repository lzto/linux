/*
 * getpmap syscall test
 * 2016 Tong Zhang<ztong@vt.edu>
 */
#include <stdio.h>
#include <stdlib.h>
#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>

#define _NR_SYS_GETPMAP (399)

struct pmap {
	unsigned long start_stack;
	unsigned long end_stack;
	unsigned long start_brk;
	unsigned long end_brk;
};

#define GETPMAP(x) \
	syscall(_NR_SYS_GETPMAP, x)

#define DUMP_PMAP(x) \
	printf("stack:0x%lx-0x%lx\n"\
		"heap:0x%lx-0x%lx\n",\
		(x)->start_stack, \
		(x)->end_stack, \
		(x)->start_brk, \
		(x)->end_brk )\

struct pmap pmap;

void benchmark()
{
	int i;
	for(i=0;i<100000;i++)
		GETPMAP(&pmap);
}

int main(int argc, char** argv)
{
#if 0
	GETPMAP(&pmap);
	DUMP_PMAP(&pmap);
	void *p = malloc(100);
	GETPMAP(&pmap);
	DUMP_PMAP(&pmap);
	free(p);
	GETPMAP(&pmap);
	DUMP_PMAP(&pmap);
#else
	benchmark();
#endif
	return 0;
}

