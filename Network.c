#include <sys/socket.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>	

/* 간단한  패킷 캡쳐 프로그램 */
int main(int argc, char **argv)
{
	int i;
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *descr;
	const u_char *packet;
	const struct pcap_pkthdr *pkthdr;
	int length=pkthdr->len;
	
	struct pcap_pkthdr hdr;			/* pcap.h */
	struct ether_header *eptr;	/* net/ethernet.h */
	unsigned short ether_type;
	struct ip *iph;			/* netinet/ip.h */
	struct tcphdr *tcph;		/* netinet/tcp.h */
	
	u_char *ptr;	/* 네트워크 헤더 정보 출력 */
	
	/* 잡을 디바이스 설정 */
	dev=pcap_lookupdev(errbuf);	
	if(dev == NULL)
	{
		printf("%s\n", errbuf);
		exit(1);
	}
	
	printf("DEV: %s\n", dev);
	
	/* 캡쳐할 디바이스 열기 */
	
	descr = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (descr == NULL)
	{
		printf("pcap_open_live(): %s\n", errbuf);
		exit(1);
	}
	
	/* 패킷 캡쳐 */

	packet = pcap_next(descr, &hdr);
	if (packet == NULL)
	{
		printf("Didn't grab packet\n");
		exit(1);

	}

	
	
	/* 이더넷 헤더 분석 */
	eptr = (struct ether_header *)packet;
	packet += sizeof(struct ether_header);
	
	if (ntohs(eptr->ether_type) == ETHERTYPE_IP)
	{

					// MAC 주소 출력(SRC_MAC, DST_MAC)
					printf("\n##### MAC 주소 #####\n");
					ptr = eptr->ether_shost;
					i = ETHER_ADDR_LEN;
					printf("Src MAC Address: ");
					do {
						printf("%s%x", ( i == ETHER_ADDR_LEN ) ? " " : ":", *ptr++);
					} while( --i > 0);
					printf("\n");

					ptr = eptr->ether_dhost;
					i = ETHER_ADDR_LEN;
					printf("Dst MAC Address : ");
					do {
						printf("%s%x", ( i == ETHER_ADDR_LEN) ? " " : ":", *ptr++);
					} while(--i > 0);
					printf("\n");
					printf("#####################\n\n");

					// IP 주소 출력 (SRC_IP, DST_IP)
					printf("#####  IP  주소 #####\n");
					iph = (struct ip *)packet;
					//printf("IP길이 : %d\n", iph->ip_hl);
					printf("프로토콜(ICMP=1,TCP=6,UDP=17 등등) : %d\n", iph->ip_p);
					printf("Src IP Address : %s\n", inet_ntoa(iph->ip_src));
					printf("Dst IP Address : %s\n", inet_ntoa(iph->ip_dst));
					printf("#####################\n\n");
					if (iph->ip_p == IPPROTO_TCP)
					{
						// TCP 포트 주소 출력 (SRC_Port, DST_Port)
						printf("####  Port 주소  ####\n");
						tcph = (struct tcphdr *)(packet + iph->ip_hl * 4);
						printf("Src Port : %d\n", ntohs(tcph->source));
						printf("Drc Port : %d\n", ntohs(tcph->dest));
						printf("#####################\n");

					}
	}

	return 0;
}


