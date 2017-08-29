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
#include <netinet/tcp.h>

#include <iostream>
#include <vector>
#include <algorithm>

#define FILTER_STRING	"udp or tcp"
#define BUF_LEN			256

#define ras_ports_test(x,y)	((x == 1718 || y == 1718) || (x == 1719 || y == 1719))

#define H225_H245_ADDR_OFF	0x0a

typedef struct h245_addr {
	uint32_t ip;
	uint16_t port;
} h245_addr_t;

std::vector<h245_addr_t> storage;

union theader {
	struct udphdr *uhdr;
	struct tcphdr *thdr; 
};

char errbuf[PCAP_ERRBUF_SIZE];
struct pcap_pkthdr header;
union theader hdr;

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
	pcap_t *pcap;
	struct bpf_program fp;
	struct ether_header *ehdr;
	bpf_u_int32 netp;
	bpf_u_int32 maskp;
	int ret;
	int counter;
	int sport, dport;

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
		pcap_perror(pcap, (char *) "pcap_compile");
		exit(1);
	}

	ret = pcap_setfilter(pcap, &fp);
	if (ret == -1) {
		pcap_perror(pcap, (char *) "pcap_setfilter");
		exit(1);
	}

	counter = 0;

	while (1) {
		int prot;

		packet = pcap_next(pcap, &header);
		counter++;

		ehdr = (struct ether_header *) packet;
		packet += ETHER_HDR_LEN;

		if (ehdr->ether_type == ETHERTYPE_IPV6) {
			prot = ((struct ip6_hdr *) packet)->ip6_nxt;
			packet += sizeof(struct ip6_hdr);
		} else {
			prot = ((struct ip *) packet)->ip_p;
			packet += sizeof(struct ip);			
		}

		if (prot == 17) {	// UDP
			struct udphdr *uhdr = (struct udphdr *) packet;
			sport = ntohs(uhdr->source);
			dport = ntohs(uhdr->dest);
			packet += sizeof(struct udphdr);
		} else if (prot == 6) {	// TCP
			struct tcphdr *thdr = (struct tcphdr *) packet;
			sport = ntohs(thdr->source);
			dport = ntohs(thdr->dest);
			packet += 4 * thdr->doff;
		} else {
			continue;
		}

		int len = header.caplen - (packet - (u_char *)ehdr);
		int tpkt_size;

		/* Test for H.225.0 RAS (UDP) */
		if (prot == 17) {
			if (!ras_ports_test(sport, dport))
				continue;

			printf("%d. H.225.0 RAS packet captured at %s", counter, ctime((time_t *) &header.ts.tv_sec));
			continue;
		}

		/* TCP, test for H.225.0 CS and H.245 (TCP) */
		if (prot == 6) {
			const u_char *tpkt = packet;

			if (len <= 4) {
				continue;
			}

			/* Test for H.245 message */
			auto func = [sport,dport](h245_addr_t& addr) {
				return (addr.port == sport) || (addr.port == dport);
			};

			std::vector<h245_addr_t>::iterator it = std::find_if(storage.begin(), storage.end(), func);
			if (it != storage.end()) {
				printf("%d. H.245 packet captured at %s", counter, ctime((time_t *) &header.ts.tv_sec));
				storage.erase(it);
			}

			/* Test for TPKT header */
			if ((packet[0] == 3) && (packet[1] == 0)) {
				//uint16_t *ptr_len = ;
				tpkt_size = ntohs(*(uint16_t *) &packet[2]);
			} else {
				continue;
			}

			/* Test if size is satisfied */
			if (tpkt_size < len)  // 4 for TPKT header itself
				continue;

			packet += 4; // Move behind TPKT header

			/* Test for Q.931 header */
			if ((packet[0] != 8) || ((packet[1] & 0xf0) != 0)) {	// H.225.0 CS
				continue;
			}

			printf("%d. H.225.0 CS packet captured at %s", counter, ctime((time_t *) &header.ts.tv_sec));

			/* Skip to type field */
			packet += 4;

			/* Type Connect */
			if (packet[0] == 0x07) {
				int con = 1;

				printf("\t H.225.0 is connect message\n");

				/* Set pointer to first element */
				packet++;
				/* 0x7e refers to user-user entity */
				while (packet[0] != 0x7e) {
					if ((packet - tpkt + packet[1]) > len) {
						con = 0;
						break;
					}
					packet += packet[1] + 2;
				}

				if (!con) {
					continue;
				}

				/* Set pointer to H.225.0 CS field. */
				packet += 4;

				if (packet[0] !=  0x22 || ((packet[1] & 0xc0) != 0xc0)) {
					printf("\tHeader doesn't match (%x %x)\n", packet[0], packet[1]);
					continue;
				}

				/* Move to IP address choice byte */
				packet += 9;

				int ipVer = -1;

				if (packet[0] == 0) {
					ipVer = 4;
				} else if (packet[0] == 0x30) {
					ipVer = 6;
				}

				if (ipVer == -1) {
					printf("\tAddress type is neither IPv4 nor IPv6");
					continue;
				}

				/* Set pointer to IP address */
				packet += 1;

				h245_addr_t addr;

				addr.ip = ntohl(*(uint32_t *) packet);
				addr.port = ntohs(*(uint16_t *) &packet[4]);

				printf("\nIP: %x, port: %d\n", addr.ip, addr.port);

				storage.push_back(addr);
			}
		}
	}

	pcap_close(pcap);
	return 0;
}
