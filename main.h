#include <cstdio>
#include <pcap.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <thread>

#include "spoof.h"
#include "getHostInfo.h"
#include "ethhdr.h"
#include "arphdr.h"
#include "iphdr.h"

void usage()
{
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}