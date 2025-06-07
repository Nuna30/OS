#include "types.h"
#include "stat.h"
#include "user.h"


void test4(int n){
	if(n > 0){
		test4(n - 1);
	}
	exit();
}

int main(int argc, char *argv[]){
	int pid;

	printf(1, "[Test4, access guard page]\n");

	printf(1, "================================== Result=================================\n");

	pid = fork();
	
	if(pid == 0)	test4(512);
	else	wait();

	printf(1, "==========================================================================\n");


	exit();	
}
