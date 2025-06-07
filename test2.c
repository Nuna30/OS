#include "types.h"
#include "stat.h"
#include "user.h"


void test2(int n){
	if(n > 0){
		test2(n - 1);
	}
	if(n == 0)	printf(1, "PASSED!\n");

	exit();
}

int main(int argc, char *argv[]){
	int pid;

	printf(1, "[Test2, stack can grow for 1 page?]\n");

	printf(1, "================================== Result=================================\n");

	pid = fork();
	
	if(pid == 0)	test2(128);
	else	wait();

	printf(1, "==========================================================================\n");

	exit();	
}
