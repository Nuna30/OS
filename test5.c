#include "types.h"
#include "stat.h"
#include "user.h"
#include "memlayout.h"

void test5(int n){
	if(n>0)
		test5(n-1);
	printf(1, "");
}

int
main(int argc, char **argv)
{
	int ppid, pid;

	// stack growth after growing process size
	printf(1, "[Test5, stack growth after growing process size]\n");

	printf(1, "================================== Result=================================\n");

	sbrk(10000);

	ppid = getpid();
	pid = fork();

	if(pid==0){
		test5(500);
		printf(1, "PASSED!\n");
		kill(ppid);
		exit();
	}
	wait();
	printf(1, "FAIL\n");
	exit();
}
