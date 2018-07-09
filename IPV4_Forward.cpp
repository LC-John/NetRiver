/*
* THIS FILE IS FOR IP FORWARD TEST
*/
#include "sysInclude.h"
#include<map>
using namespace std;

// system support
extern void fwd_LocalRcv(char *pBuffer, int length);

extern void fwd_SendtoLower(char *pBuffer, int length, unsigned int nexthop);

extern void fwd_DiscardPkt(char *pBuffer, int type);

extern unsigned int getIpv4Address( );

// implemented by students

/* RouteTable <DstAddr, nexthop> */
map<int, int> RouteTable;

/* Initializing the RouteTable */
void stud_Route_Init()
{
	RouteTable.clear();
	return;
}

/* Adding a new entry to the RouteTable */
void stud_route_add(stud_route_msg* proute)
{
	int mask = 0xFFFFFFFF << (32 - htonl(proute->masklen));
	int DstAddr = ntohl(proute->dest) & mask;
	int NextHop = ntohl(proute->nexthop);
	RouteTable.insert(std::pair<int, int>(DstAddr, NextHop));
	return;
}

/* Dealing with the reception and forwarding */
int stud_fwd_deal(char* pBuffer, int length)
{
	int IHL = pBuffer[0] & 0xf;
	int TTL = (int)pBuffer[8];
	int DstAddr = ntohl(*(unsigned *)(&pBuffer[16]));

	// Local, no forwording.
	if (DstAddr == getIpv4Address())
	{
		fwd_LocalRcv(pBuffer, length);
		return 0;
	}
	// TTL error.
	if (TTL <= 0)
	{
		fwd_DiscardPkt(pBuffer, STUD_FORWARD_TEST_TTLERROR);
		return 1;
	}

	map<int, int>::iterator ii = RouteTable.find(DstAddr);
	// No route.
	if (ii == RouteTable.end()) 
	{
		fwd_DiscardPkt(pBuffer, STUD_FORWARD_TEST_NOROUTE);
		return 1;
	}

	unsigned char* Buffer = (unsigned char *)malloc(length);
	memcpy(Buffer, pBuffer, length);

	// Set TTL and header check sum.
	Buffer[8] = TTL - 1;
	unsigned int HeaderCheckSum = 0;
	memset(&Buffer[10], 0, sizeof(short));
	for (int i = 0; i < 4 * IHL; i += 2)
		HeaderCheckSum += ((Buffer[i] & 0xFF) << 8) + (Buffer[i + 1] & 0xFF);
	HeaderCheckSum += (HeaderCheckSum >> 16);
	HeaderCheckSum = ~HeaderCheckSum;
	Buffer[10] = (unsigned short)HeaderCheckSum >> 8;
	Buffer[11] = (unsigned short)HeaderCheckSum & 0xFF;

	// Send the package.
	fwd_SendtoLower((char *)Buffer, length, (*ii).second);

	return 0;
}