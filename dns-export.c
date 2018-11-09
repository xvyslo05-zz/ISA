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
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define SIZE_ETHERNET 14



/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

	/* Ethernet header */
	struct sniff_ethernet {
		u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
		u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
		u_short ether_type; /* IP? ARP? RARP? etc */
	};

	/* IP header */
	struct sniff_ip {
		u_char ip_vhl;		/* version << 4 | header length >> 2 */
		u_char ip_tos;		/* type of service */
		u_short ip_len;		/* total length */
		u_short ip_id;		/* identification */
		u_short ip_off;		/* fragment offset field */
	#define IP_RF 0x8000		/* reserved fragment flag */
	#define IP_DF 0x4000		/* dont fragment flag */
	#define IP_MF 0x2000		/* more fragments flag */
	#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
		u_char ip_ttl;		/* time to live */
		u_char ip_p;		/* protocol */
		u_short ip_sum;		/* checksum */
		struct in_addr ip_src, in_dst; /* source and dest address */
	};
	#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
	#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

	/* TCP header */
	typedef u_int tcp_seq;

	struct sniff_tcp {
		u_short th_sport;	/* source port */
		u_short th_dport;	/* destination port */
		tcp_seq th_seq;		/* sequence number */
		tcp_seq th_ack;		/* acknowledgement number */
		u_char th_offx2;	/* data offset, rsvd */
	#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
		u_char th_flags;
	#define TH_FIN 0x01
	#define TH_SYN 0x02
	#define TH_RST 0x04
	#define TH_PUSH 0x08
	#define TH_ACK 0x10
	#define TH_URG 0x20
	#define TH_ECE 0x40
	#define TH_CWR 0x80
	#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
		u_short th_win;		/* window */
		u_short th_sum;		/* checksum */
		u_short th_urp;		/* urgent pointer */
};

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


	const struct sniff_ethernet *ethernet; /* The ethernet header */
	const struct sniff_ip *ip; /* The IP header */
	const struct sniff_tcp *tcp; /* The TCP header */
	const char *payload; /* Packet payload */

	u_int size_ip;
	u_int size_tcp;

	ethernet = (struct sniff_ethernet*)(packet);
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

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
