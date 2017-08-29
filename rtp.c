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

#define rtp_ports_test(s,d)		!((s & 1) || (d & 1))
#define rtp_pt_test(x)	(((x <= 34) || ((x >= 96) && (x <= 127))))

char errbuf[PCAP_ERRBUF_SIZE];

int main(int argc, char *argv[])
{
	const u_char *packet;
	//char buf[BUF_LEN];
	pcap_t *pcap;
	struct bpf_program fp;
	struct pcap_pkthdr header;
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

		//printf("L2:\n");
		ehdr = (struct ether_header *) packet;
		//printf("\tSRC MAC: %s\n", ether_ntoa((struct ether_addr *) ehdr->ether_shost));
		//printf("\tDST MAC: %s\n", ether_ntoa((struct ether_addr *) ehdr->ether_dhost));
		packet += ETHER_HDR_LEN;

		//printf("L3:\n");
		if (ehdr->ether_type == ETHERTYPE_IPV6) {
			//ip6hdr = (struct ip6_hdr *) packet;
			//printf("\tSRC IP: %s\n", inet_ntop(AF_INET6, (struct in6_addr *) &ip6hdr->ip6_src, buf, BUF_LEN-1));
			//printf("\tSRC IP: %s\n", inet_ntop(AF_INET6, (struct in6_addr *) &ip6hdr->ip6_dst, buf, BUF_LEN-1));
			//printf("\tHop Limit: %u\n", ip6hdr->ip6_ctlun.ip6_un1.ip6_un1_hlim);
			packet += sizeof(struct ip6_hdr);
		} else {
			if (((struct ip *) packet)->ip_p != 17)
				continue;
			//iphdr = (struct ip *) packet;
			//printf("\tSRC IP: %s\n", inet_ntop(AF_INET, (struct in_addr *) &iphdr->ip_src, buf, BUF_LEN-1));
			//printf("\tDST IP: %s\n", inet_ntop(AF_INET, (struct in_addr *) &iphdr->ip_dst, buf, BUF_LEN-1));
			//printf("\tTTL: %u\n", iphdr->ip_ttl);
			packet += sizeof(struct ip);
		}

		//printf("L4:\n");
		uhdr = (struct udphdr *) packet;
		sport = ntohs(uhdr->source);
		dport = ntohs(uhdr->dest);
		//printf("\tSRC PORT: %u\n", sport);
		//printf("\tDST PORT: %u\n", dport);
		packet += sizeof(struct udphdr);

		int tempSize = 0;
		int len = header.caplen - (packet - (u_char *)ehdr);

		if ((len < 12) || !rtp_ports_test(sport, dport))
			continue;

		uint8_t ver = packet[0] & 0xe0;
		uint8_t pt = packet[1] & 0x7f;

		if (ver & 0x20) {
			tempSize = packet[len-1];
		}

		tempSize += (packet[0] & 0x0f) * 4;

		if ((len - tempSize) < 12)
			continue;

		if ( ((ver & 0xc0) == 0x80) && rtp_pt_test(pt) ) {
			printf("%d. Packet captured at %s", counter, ctime((time_t *) &header.ts.tv_sec));
			printf("\nPayload length is: %d\n", len);
			printf("\nTempsize length is: %d\n", tempSize);
			printf("Capture length is: %d\n\n", header.caplen);
			for (int i = 0; i < len; i++)
				printf("0x%02x ", packet[i]);
			printf("\n\n");
		}
	}

	pcap_close(pcap);
	return 0;
}
