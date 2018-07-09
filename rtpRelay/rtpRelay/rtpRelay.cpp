// Make 100% sure WIN32 is defined
#ifndef WIN32
#define WIN32    100  // 100 == NT version 1.0
#endif

#include <iostream>
#include <pcap.h>
/* 4 bytes IP address */
typedef struct ip_address {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

/* IPv4 header */
typedef struct ip_header {
	u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
	u_char  tos;            // Type of service 
	u_short tlen;           // Total length 
	u_short identification; // Identification
	u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
	u_char  ttl;            // Time to live
	u_char  proto;          // Protocol
	u_short crc;            // Header checksum
	ip_address  saddr;      // Source address
	ip_address  daddr;      // Destination address
	u_int   op_pad;         // Option + Padding
}ip_header;

/* UDP header*/
typedef struct udp_header {
	u_short sport;          // Source port
	u_short dport;          // Destination port
	u_short len;            // Datagram length
	u_short crc;            // Checksum
}udp_header;

#define SIZE_UDP        8               /* length of UDP header */
#define SIZE_ETHERNET 14

/* prototype of the packet handler */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

using namespace std;

int main()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i = 0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];

	/* Retrieve the device list */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	/* Print the list */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}
	cout << "Enter the interface number" << endl;
	cin >> inum; 

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);

	/* Open the device */
	/* Open the adapter */
	if ((adhandle = pcap_open_live(d->name,	// name of the device
		65536,			// portion of the packet to capture. 
						// 65536 grants that the whole packet will be captured on all the MACs.
		1,				// promiscuous mode (nonzero means promiscuous)
		1000,			// read timeout
		errbuf			// error buffer
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on %s...\n", d->description);
	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);

	/* start the capture */
	pcap_loop(adhandle, 0, packet_handler, NULL);

	pcap_close(adhandle);
	return 0;

}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct tm *ltime;
	char timestr[16];
	time_t local_tv_sec;
	ip_header *ih;
	udp_header *uh;
	u_int ip_len;
	u_short sport, dport;

	/*
	* unused parameters
	*/
	(VOID)(param);

	/* retireve the position of the ip header */
	ih = (ip_header *)(pkt_data +
		SIZE_ETHERNET); //length of ethernet header

	/* retireve the position of the udp header */
	ip_len = (ih->ver_ihl & 0xf) * 4;
	uh = (udp_header *)((u_char*)ih + ip_len);

	/* convert from network byte order to host byte order */
	sport = ntohs(uh->sport);
	dport = ntohs(uh->dport);

	/* print ip addresses and udp ports */
	/*cout << ih->saddr.byte1 << endl << ih->saddr.byte2 << endl << ih->saddr.byte3
		<< endl << ih->saddr.byte4 << endl << sport << endl << ih->daddr.byte1
		<< endl << ih->daddr.byte2 << ih->daddr.byte3 << endl << ih->daddr.byte4 << endl << dport;
		*/
	if (ih->proto == IPPROTO_UDP) {
		/* declare pointers to packet headers */
		const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
		const u_char *payload;                    /* Packet payload */

		int size_ip = ip_len;
		int size_payload;

		/* define ethernet header */
		ethernet = (struct sniff_ethernet*)(pkt_data);

		cout << "UDP packet" << endl;
		//cout << "Source port is :" << ntohs(udp->uh_sport) << " Destination port is : " << ntohs(udp->uh_dport) << endl;
		/*
		*  OK, this packet is UDP.
		*/

		/* define/compute udp payload (segment) offset */
		payload = (u_char *)(pkt_data + SIZE_ETHERNET + size_ip + SIZE_UDP);

		/* compute udp payload (segment) size */
		size_payload = ntohs(ih->tlen) - (size_ip + SIZE_UDP);
		if (size_payload > ntohs(uh->len))
			size_payload = ntohs(uh->len);

		/*
		* Print payload data; it might be binary, so don't just
		* treat it as a string.
		*/
		if (size_payload > 0) {
			cout << "   IP tlen : " << ih->tlen << endl;
			cout << "   Payload : " << size_payload << endl;
			cout << "   length  : " << uh->len << endl;
			cout << "   dest port : " << uh->dport << endl;
			cout << "   src port  : " << uh->sport << endl;
		}
	}

	/* convert the timestamp to readable format */
	//local_tv_sec = header->ts.tv_sec;
	//ltime = localtime_s(&local_tv_sec);
	//strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

	//printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
	//cout << header->len << endl;

}