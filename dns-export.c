// ISA PROJEKT
// VYSLOUZIL Robin
// xvyslo05@stud.fit.vutbr.cz

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <pcap.h>
#include <unistd.h>
#include <syslog.h>

#define SIZE_ETHERNET 14


/*
Structure of inputs
*/

typedef struct args {
	char * inputFile;
	char * interfaceType;
	char * address;
	char errbuf[PCAP_ERRBUF_SIZE];
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

	FILE * inputFile;

	int opt;

	if(argc == 1) {
		a.operation = 0;
	} else if(argc == 2) {
		if(strcmp(argv[1], "-h") == 0)
			a.operation = 1;
		else
			a.operation = 0;
	} else if(argc > 2) {
		while((opt = getopt(argc, argv, "r:i:s:t:")) != 1) {
			switch(opt) {
				case '?':
					a.operation = 0;
					return a;
					break;
				case 'r':
					inputFile = fopen(optarg, "r");

					if(inputFile == NULL) {
						fprintf(stderr, "ERROR, .pcap file does not exist\n");
						a.operation = 0;
						return a;
					}

					fclose(inputFile);

					a.inputFile = optarg;
					a.operation = 2;
					break;

				case 'i':
					a.interfaceType = optarg;
					a.operation = 3;
					break;

				case 's':
					a.address = optarg;
					a.operation = 4;
					break;

				case 't':
					a.countingTime = atoi(optarg);

					if(a.countingTime <= 0) {
						a.operation = 0;
						return a;
						break;
					}
					break;
				default:
					return a;
			}
		}
	}

	return a;
}

void catched_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	static int count = 1;

	if(count == 45)
		return;

	printf("%d\n", count);

	printf("%s\n", packet);

	count++;

}

void parsePcapFile() {

}

int sniffOnInterface() {

	char port[8] = "port 53";
	struct bpf_program fp;
	bpf_u_int32 mask;
	bpf_u_int32 net;
	// const u_char *packet;
	struct pcap_pkthdr header;

	pcap_t *handle;

	if (pcap_lookupnet(var.interfaceType, &net, &mask, var.errbuf) == -1) {
		fprintf(stderr, "Can't get netmask for device %s\n", var.interfaceType);
		net = 0;
		mask = 0;
		return(2);
	}

	handle = pcap_open_live(var.interfaceType, BUFSIZ, 1, 1000, var.errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", var.interfaceType, var.errbuf);
		return(2);
	}

	if(pcap_compile(handle, &fp, port, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", port, pcap_geterr(handle));
		return(2);
	}

	if(pcap_setfilter(handle, &fp) ==  -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", port, pcap_geterr(handle));
		return(2);
	}

	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", var.interfaceType);
		return(2);
	}


	pcap_loop(handle, 30, catched_packet, NULL);

	printf("delka packetu je %d\n", header.len);


	pcap_freecode(&fp);
	pcap_close(handle);

	printf("U Pinkasu zhasli\n");
	return 0;
}

void sniffOnAddress() {

}

void sendDataToSyslog() {

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
		case 2:
			printf("%s\n", var.inputFile);
			parsePcapFile();
			break;
		case 3:
			printf("%s\n", var.interfaceType);
			sniffOnInterface();
			break;
		case 4:
			printf("%s\n", var.address);
			sniffOnAddress();
			break;
	}


	return 0;
}
