#include <sys/socket.h>
#include <sys/ioctl.h>
#include <asm/types.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <arpa/inet.h>

#define BUF_SIZE 43
#define ETH_P_ICMP 0x0800

unsigned char buffer[BUF_SIZE];

int send_icmp(int fd, int ifindex, uint32_t src, uint32_t dst)
{
	// F8:1A:67:C7:F4:90
	buffer[0] = 0xf8;
	buffer[1] = 0x1a;
	buffer[2] = 0x67;
	buffer[3] = 0xc7;
	buffer[4] = 0xf4;
	buffer[5] = 0x90;

	// src mac
	/*
	buffer[6] = macpref[0];
	buffer[7] = macpref[1];
	buffer[8] = macpref[2];
	buffer[9] = macsuf[0];
	buffer[10] = macsuf[1];
	buffer[11] = macsuf[2];
	*/

	// source ip
	buffer[26] = (src) & 0xFF;
	buffer[27] = (src >> 8) & 0xFF;
	buffer[28] = (src >> 16) & 0xFF;
	buffer[29] = (src >> 24) & 0xFF;
	// destination ip
	buffer[30] = (dst) & 0xFF;
	buffer[31] = (dst >> 8) & 0xFF;
	buffer[32] = (dst >> 16) & 0xFF;
	buffer[33] = (dst >> 24) & 0xFF;

	// icmp
	buffer[12] = 0x08;
	buffer[13] = 0x00;
	
	// version
	buffer[14] = 0x45;
	
	// size
	buffer[15] = 0x00;
	buffer[16] = 0x00;
	
	// ipv4 stuff
	buffer[17] = 0x1d;
	buffer[18] = 0xc6;
	buffer[19] = 0xec;
	buffer[20] = 0x00;
	buffer[21] = 0x00;
	buffer[22] = 0x80;
	buffer[23] = 0x01;
	buffer[24] = 0x00;
	buffer[25] = 0x00;
	
	// icmp payload
	buffer[34] = 0x08;
	buffer[35] = 0x00;
	buffer[36] = 0x42;
	buffer[37] = 0xbf;
	buffer[38] = 0x00;
	buffer[39] = 0x01;
	buffer[40] = 0x54;
	buffer[41] = 0x3f;
	buffer[42] = 0x61;

	if (send(fd, buffer, BUF_SIZE, 0) == -1)
	{
		perror("sendto():");
		return -1;
	}

	return 0;
}

int get_if_info(const char *ifname, int *ifindex)
{
	struct ifreq ifr;
	int sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ICMP));
	if (sd <= 0)
	{
		perror("socket()");
		return -1;
	}
	if (strlen(ifname) > (IFNAMSIZ - 1))
	{
		printf("Too long interface name, MAX=%i\n", IFNAMSIZ - 1);
		return -1;
	}

	strcpy(ifr.ifr_name, ifname);

	if (ioctl(sd, SIOCGIFINDEX, &ifr) == -1)
	{
		perror("SIOCGIFINDEX");
		close(sd);
		return -1;
	}
	*ifindex = ifr.ifr_ifindex;

	return 0;
}

int bind_icmp(int ifindex, int *fd)
{
	*fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ICMP));
	if (*fd < 1)
	{
		perror("socket()");
		return -1;
	}

	struct sockaddr_ll sll;
	memset(&sll, 0, sizeof(struct sockaddr_ll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifindex;
	
	if (bind(*fd, (struct sockaddr*) &sll, sizeof(struct sockaddr_ll)) < 0)
	{
		perror("bind");
		close(*fd);
		return -1;
	}

	return 0;
}

unsigned char *macpref = buffer+6;
unsigned char *macsuf = buffer+9;

int increment_mac(int idx)
{
	if (macsuf[idx] >= 255)
	{
		if (idx == 0)
			return 1;
		macsuf[idx] = 0;
		return increment_mac(idx - 1);
	}
	macsuf[idx]++;
	
	return 0;
}


int main(int argc, const char **argv)
{
	int ifindex;
	int icmp_fd;
	
	if (argc != 4)
	{
		printf("Usage: %s if src dst\n", argv[0]);
		return 1;
	}
	
	uint32_t src = inet_addr(argv[2]);
	uint32_t dst = inet_addr(argv[3]);
	
	if (get_if_info(argv[1], &ifindex) || bind_icmp(ifindex, &icmp_fd))
		return 3;

	FILE *fin = fopen ("mac.txt", "r");
	if (!fin)
	{
		printf ("Can\'t open input file\n");
		return 2;
	}
	
	char chunk[7];
	
	while (fscanf (fin, "%s", chunk) != EOF)
	{
		printf ("%s\n", chunk);
		sscanf (chunk,     "%2hhx", macpref);
		sscanf (chunk + 2, "%2hhx", macpref + 1);
		sscanf (chunk + 4, "%2hhx", macpref + 2);

		macsuf[0] = 0;
		macsuf[1] = 0;
		macsuf[2] = 0;
		while (!increment_mac(2))
		{
			//printf ("%x:%x:%x:%x:%x:%x\n", macpref[0], macpref[1], macpref[2], macsuf[0], macsuf[1], macsuf[2]);
			if (send_icmp(icmp_fd, ifindex, src, dst))
				return 4;
		}
	}

	return 0;
}
