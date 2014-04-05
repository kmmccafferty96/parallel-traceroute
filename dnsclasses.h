//Author: Zain Shamsi

#include "ICMPheader.h"

using namespace std;

/* query class */
#define DNS_INET 1 

/* DNS query types */ 
#define DNS_A  1			/* name -> IP */ 
#define DNS_NS  2			/* name server */ 
#define DNS_CNAME  5		/* canonical name */ 
#define DNS_PTR  12			/* IP->name */ 
#define DNS_HINFO  13		/* host info */ 
#define DNS_MX  15			/* mail exchange */ 
#define DNS_AXFR  252		/* request for zone transfer */ 
#define DNS_ANY  255		/* all records */ 

/* flags */ 
#define DNS_QUERY  (0 << 15)   /* 0 = query; 1 = response */ 
#define DNS_RESPONSE (1 << 15) 
 
#define DNS_STDQUERY (0)    /* opcode - 4 bits */ 
#define DNS_INVQUERY (1 << 11) 
#define DNS_SRVSTATUS (1 << 12) 
 
#define DNS_AA  (1 << 10)   /* authoritative answer */ 
#define DNS_TC  (1 << 9)   /* truncated */ 
#define DNS_RD  (1 << 8)   /* recursion desired */ 
#define DNS_RA  (1 << 7)   /* recursion available */

/* result codes */
#define DNS_OK  0  /* rcode = reply codes */ 
#define DNS_FORMAT 1  /* format error (unable to interpret */
#define DNS_SERVERFAIL 2  /* server failure */ 
#define DNS_ERROR  3  /* no DNS entry */ 
#define DNS_NOTIMPL 4  /* not implemented */ 
#define DNS_REFUSED 5  /* server refused the query */ 


class queryHeader { 
public:
	u_short qtype; 
	u_short qclass; 
};

class fixedDNSheader { 
public:
	u_short ID; 
	u_short flags; 
	u_short questions; 
	u_short answers;
	u_short authority;
	u_short additional;
}; 

#pragma pack(push)
#pragma pack(1)
class fixedRR {
public:
	u_short atype;
	u_short aclass;
	u_int ttl;
	u_short data_length;
};
#pragma pack(pop)

int SendDNS(SOCKET DNSSocket, sockaddr_in RecvAddr, char* IP, int ttl);
int RecvDNS(SOCKET DNSSocket, vector<PingResult> *pr);
char* getDNSServer(void);
void MakeDNSQuestion (char* buf, char* host);
char* ReverseIP(char* IP);
string ReverseIPString(char* IP);
char* UnMakeDNSQuestion (char* buf);
char* GetName(char* buffer, char* full_response, int *length);
