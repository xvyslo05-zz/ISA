// ISA PROJEKT
// VYSLOUZIL Robin
// xvyslo05@stud.fit.vutbr.cz

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <pcap.h>
#include <unistd.h>


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


/*
Prints help on stdout
*/

void PrintHelp() {
	printf("[-h] - prints help on stdout. Use as an only argument\n"
			"[-r file.pcap] - chooses which file is going to be examinated\n"
			"[-i interface] - chooses on which interface are we listening on\n"
			"[-s address] - chooses hostname/IPv4/IPv6 adress of SYSLOG server\n"
			"[-t time] - sets timelenght of the examination. Implicit value is 60s\n");
	exit(0);
}


/*
Checks input arguments

@param int argc represents number of input arguments
@param char argv represents parameters of input arguments
@return a returns structure of input arguments
*/

args_t CheckArgs(int argc, char * argv[]) {

	args_t a;

	a.operation = 0;
	a.countingTime = 60;

	int opt;

	if(argc == 1) {
		a.operation = 0;
	} else if(argc == 2) {
		if(strcmp(argv[1], "-h") == 0)
			a.operation = 1;
		else
			a.operation = 0;
	} else if(argc > 2) {
		while((opt = getopt(argc, argv, "rist")) != 1) {
			switch(opt) {
				case '?':
					a.operation = 0;
					return a;
					break;
			}
		}
	}

	return a;
}

/*
Main switch

@param int argc represents number of input arguments
@param char argv represents parameters of input arguments
@return -1, 0 or 1
*/

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
