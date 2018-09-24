// ISA PROJEKT
// VYSLOUZIL Robin
// xvyslo05@stud.fit.vutbr.cz

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>


/*
Structure of inputs
*/

typedef struct args {
	char * inputFile;
	char * interfaceType;
	char * address;
	int countingTime;
	int operation;
} args_t;

args_t var;

void PrintHelp() {
	printf("[-h] - prints help on stdout. Only argument\n"
			"[-r file.pcap] - chooses which file is going to be examinated\n"
			"[-i interface] - chooses on which interface are we listening on\n"
			"[-s adress] - chooses hostname/IPv4/IPv6 adress of SYSLOG server\n"
			"[-t time] - sets timelenght of the examination. Implicit value is 60s\n");
	exit(0);
}

args_t CheckArgs(int argc, char * argv[]) {

	args_t a;

	a.operation = 0;
	a.countingTime = 60;

	if(argc == 2) {
		if(strcmp(argv[1], "-h") == 0)
			a.operation = 1;
		else
			a.operation = 0;
	}


	return a;
}


int main(int argc, char * argv[]) {

	var = CheckArgs(argc, argv);

	switch(var.operation){
		case 0:
			fprintf(stderr, "INPUT ERROR, use -h for help option\n");
			return -1;
			break;
		case 1:
			PrintHelp();
			return 0;
			break;
	}


	return 0;
}
