#include "types.h"
#include "stat.h"
#include "user.h"


void test3(int n){
	if(n > 0){
		test3(n - 1);
	}
	if(n == 0)	printf(1, "PASSED!\n");
	exit();
}

int main(int argc, char *argv[]){
	int pid;

	printf(1, "[Test3, stack can grow for 4 pages?]\n");

	printf(1, "================================== Result=================================\n");

	pid = fork();
	
	if(pid == 0)	test3(384);
	else	wait();

	printf(1, "==========================================================================\n");

	exit();	
}
