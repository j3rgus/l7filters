#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <pcap.h>
#include <time.h>
#include <errno.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>

#define FILTER_STRING	"udp"
#define BUF_LEN			256

#define rtcp_ports_test(s,d)	((s & 1) && (d & 1))

char errbuf[PCAP_ERRBUF_SIZE];
struct pcap_pkthdr header;

void printPacket(const u_char *packet, int len)
{
	printf("Packet captured at %s", ctime((time_t *) &header.ts.tv_sec));
	printf("\nPayload length is: %d\n", len);
	printf("Capture length is: %d\n\n", header.caplen);
	for (int i = 0; i < len; i++)
		printf("0x%02x ", packet[i]);
	printf("\n\n");
}

int main(int argc, char *argv[])
{
	const u_char *packet;
	//char buf[BUF_LEN];
	pcap_t *pcap;
	struct bpf_program fp;
	struct ether_header *ehdr;
	//struct ip *iphdr;
	//struct ip6_hdr *ip6hdr;
	struct udphdr *uhdr;
	bpf_u_int32 netp;
	bpf_u_int32 maskp;
	int ret;
	int counter, sport, dport;

	if (argc < 2) {
		fprintf(stderr, "Need interface as a parameter!\n");
		exit(1);
	}

	ret = pcap_lookupnet(argv[1], &netp, &maskp, errbuf);
	if (ret == -1) {
		fprintf(stderr, "%s\n", errbuf);
		exit(1);
	}

	pcap = pcap_open_live(argv[1], 2000, 0, 0, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "%s\n", errbuf);
		exit(1);
	}

	ret = pcap_datalink(pcap);
	if (ret != DLT_EN10MB) {
		fprintf(stderr, "Interface %s doesn't provide Ethernet headers!\n", argv[1]);
		exit(1);
	}

	ret = pcap_compile(pcap, &fp, FILTER_STRING, 0, netp);
	if (ret == -1) {
		pcap_perror(pcap, "pcap_compile");
		exit(1);
	}

	ret = pcap_setfilter(pcap, &fp);
	if (ret == -1) {
		pcap_perror(pcap, "pcap_setfilter");
		exit(1);
	}

	counter = 0;

	while (1) {
		counter++;
		packet = pcap_next(pcap, &header);

		ehdr = (struct ether_header *) packet;
		packet += ETHER_HDR_LEN;

		if (ehdr->ether_type == ETHERTYPE_IPV6) {
			if ( ((struct ip6_hdr *) packet)->ip6_nxt != 17 )
				continue;
			packet += sizeof(struct ip6_hdr);
		} else {
			if (((struct ip *) packet)->ip_p != 17)
				continue;
			packet += sizeof(struct ip);
		}

		uhdr = (struct udphdr *) packet;
		sport = ntohs(uhdr->source);
		dport = ntohs(uhdr->dest);
		packet += sizeof(struct udphdr);

		int len = header.caplen - (packet - (u_char *)ehdr);

		if ((len > 255) || !rtcp_ports_test(sport, dport))
			continue;

		uint8_t ver = packet[0] & 0xc0;
		uint8_t pt = packet[1];

		if (ver == 0x80) {
			switch (pt) {
			case 200:
				printf("%d. Sender Report RTCP Packet\n", counter++);
				printPacket(packet, len);
				break;
			case 201:
				printf("%d. Receiver Report RTCP Packet\n", counter++);
				printPacket(packet, len);
				break;
			case 202:
				printf("%d. Source Description RTCP Packet\n", counter++);
				printPacket(packet, len);
				break;
			case 203:
				printf("%d. Goodbye RTCP Packet\n", counter++);
				printPacket(packet, len);
				break;
			case 204:
				printf("%d. Application-Defined RTCP Packet\n", counter++);
				printPacket(packet, len);
				break;
			}
		}
	}

	pcap_close(pcap);
	return 0;
}
