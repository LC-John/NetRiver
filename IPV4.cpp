/*
* THIS FILE IS FOR IP TEST
*/
// system support
#include "sysInclude.h"

extern void ip_DiscardPkt(char* pBuffer,int type);

extern void ip_SendtoLower(char*pBuffer,int length);

extern void ip_SendtoUp(char *pBuffer,int length);

extern unsigned int getIpv4Address();

// implemented by students

// IPv4 Version = 4
#define VERSION_DEFAULT ((unsigned int)(4));
// IHL = 5
#define IHL_DEFAULT ((unsigned int)(5));

unsigned int getVersion(char* pBuffer) { return (unsigned)pBuffer[0] >> 4; }
unsigned int getIHL(char* pBuffer) { return (unsigned)pBuffer[0] & 0xF; }
unsigned int getTTL(char* pBuffer) { return (unsigned)pBuffer[8]; }
unsigned int getDstAddr(char* pBuffer) { return ntohl(*(unsigned int *)(&pBuffer[16])); }
unsigned int getCheckSum(char* pBuffer)
{
	unsigned int HeaderCheckSum = 0;
	for (int i = 0; i < 20; i += 2) {
		HeaderCheckSum += ((pBuffer[i] & 0xFF) << 8) + (pBuffer[i + 1] & 0xFF);
	}
	HeaderCheckSum += (HeaderCheckSum >> 16);
	return HeaderCheckSum;
}

int stud_ip_recv(char* pBuffer, unsigned short length)
{
	unsigned int Version = getVersion(pBuffer);
	unsigned int IHL = getIHL(pBuffer);
	unsigned int TTL = getTTL(pBuffer);
	unsigned int DstAddr = getDstAddr(pBuffer);
	unsigned int HeaderCheckSum = getCheckSum(pBuffer);

	if (Version != 4) {
		ip_DiscardPkt(pBuffer, STUD_IP_TEST_VERSION_ERROR);
		return 1;
	}
	if (IHL < 5) {
		ip_DiscardPkt(pBuffer, STUD_IP_TEST_HEADLEN_ERROR);
		return 1;
	}
	if (!TTL) {
		ip_DiscardPkt(pBuffer, STUD_IP_TEST_TTL_ERROR);
		return 1;
	}
	if (DstAddr != getIpv4Address() && DstAddr != 0xFFFFFFFF) {
		ip_DiscardPkt(pBuffer, STUD_IP_TEST_DESTINATION_ERROR);
		return 1;
	}
	if ((unsigned short)(~HeaderCheckSum)) {
		ip_DiscardPkt(pBuffer, STUD_IP_TEST_CHECKSUM_ERROR);
		return 1;
	}

	ip_SendtoUp(pBuffer, length);
	return 0;
}

void setVersionIHL(char* Buffer) { Buffer[0] = VERSION_DEFAULT << 4 | IHL_DEFAULT; }
void setLength(char* Buffer, unsigned int TotalLen) { Buffer[2] = TotalLen >> 8; Buffer[3] = TotalLen; }
void setTTL(char* Buffer, byte ttl) { Buffer[8] = ttl; }
void setProtocol(char* Buffer, byte protocol) { Buffer[9] = protocol; }
void setSrcAddr(char* Buffer, unsigned int srcAddr)
{
	Buffer[12] = srcAddr >> 24;
	Buffer[13] = srcAddr >> 16;
	Buffer[14] = srcAddr >> 8;
	Buffer[15] = srcAddr;
}
void setDstAddr(char* Buffer, unsigned int dstAddr)
{
	Buffer[16] = dstAddr >> 24;
	Buffer[17] = dstAddr >> 16;
	Buffer[18] = dstAddr >> 8;
	Buffer[19] = dstAddr;
}
void setCheckSum(char* Buffer)
{
	unsigned int HeaderCheckSum = 0;
	for (int i = 0; i < 20; i += 2)
		HeaderCheckSum += ((Buffer[i] & 0xFF) << 8) + (Buffer[i + 1] & 0xFF);
	HeaderCheckSum += HeaderCheckSum >> 16;
	HeaderCheckSum = ~HeaderCheckSum;
	Buffer[10] = (char)((unsigned short)HeaderCheckSum >> 8);
	Buffer[11] = (char)((unsigned short)HeaderCheckSum & 0xFF);
}
void setContent(char* Buffer, char* pBuffer, unsigned short len) { memcpy(Buffer + 20, pBuffer, len); }

int stud_ip_Upsend(char* pBuffer, unsigned short len, unsigned int srcAddr,
                   unsigned int dstAddr, byte protocol, byte ttl)
{
	unsigned int TotalLen = 4 * IHL_DEFAULT + len;
	unsigned char* Buffer = (unsigned char*) malloc(TotalLen);

	memset(Buffer, 0, TotalLen);

	setVersionIHL(Buffer);
	setLength(Buffer, TotalLen);
	setTTL(Buffer, ttl);
	setProtocol(Buffer, protocol);
	setSrcAddr(Buffer, srcAddr);
	setDstAddr(Buffer, dstAddr);
	setCheckSum(Buffer);
	setContent(Buffer, pBuffer, len);

	ip_SendtoLower((char*)Buffer, TotalLen);

	return 0;
}