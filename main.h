#include <cstdio>
#include <iostream>
#include <pcap.h>
#include "getHostInfo.cpp"
#include "ethhdr.h"
#include "arphdr.h"
#include "iphdr.h"
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include "infection.cpp"

void usage()
{
	printf("syntax : arp-spoof <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1\n");
}