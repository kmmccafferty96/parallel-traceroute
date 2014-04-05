/*
Author: Zain Shamsi
*/
#include "dnsclasses.h"
#include <set>
using namespace std;

sockaddr_in CreateServer(char* address);
SOCKET CreateSocket();
u_short ip_checksum (u_short * buffer, int size);
void SendICMP(SOCKET sock, sockaddr_in server, int ttl, int timeout);
void RecICMP(SOCKET sock, sockaddr_in server);
SOCKET CreateDNSSocket();
sockaddr_in CreateDNSServer();
void PrintTraceRoute();

multiset<HeapContainer> timeout_queue;
vector<PingResult> p;
int host_hop;

int main(int argc, char* argv[]){	
	WSADATA wsaData = {0};

	if (argc < 2){
		printf("Usage: %s [IP or Hostname]\n", argv[0]);
		return 1;
	}	
	
	// Initialize Winsock
    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        wprintf(L"WSAStartup failed: %d\n", iResult);
        return 1;
    }

	struct sockaddr_in server = CreateServer(argv[1]);
	SOCKET sock = CreateSocket();

	//send 3 ICMP requests for each ttl
	for (int i = 1; i <= 30; i++){
		for (int j = 0; j < 3; j++)
			SendICMP(sock, server, i, timeGetTime() + DEFAULT_TIMEOUT);
		p.push_back(PingResult(i));
	}

	RecICMP(sock, server);
	
	PrintTraceRoute();

	closesocket (sock); 
	system("pause");
	return 0;
}

void SendICMP(SOCKET sock, sockaddr_in server, int ttl, int timeout){
	int ret;

	// buffer for the ICMP header 
	u_char send_buf[MAX_ICMP_SIZE];  /* IP header is not present here */ 
 
	ICMPHeader *icmp = (ICMPHeader *) send_buf; 
 
	// set up the echo request 
	// no need to flip the byte order since fields are 1 byte each 
	icmp->type = ICMP_ECHO_REQUEST; 
	icmp->code = 0; 
 
	// set up ID/SEQ fields as needed 
	icmp->id = (u_short) GetCurrentProcessId (); 
	icmp->seq = ttl;
	// initialize checksum to zero 
	icmp->checksum = 0; 
 
	/* calculate the checksum */ 
	int packet_size = sizeof(ICMPHeader);   // 8 bytes 
	icmp->checksum = ip_checksum ((u_short *) send_buf, packet_size); 
 
	// set our TTL
	if (setsockopt (sock, IPPROTO_IP, IP_TTL, (const char *) &ttl, sizeof (ttl)) == SOCKET_ERROR) { 
		perror ("setsockopt failed\n"); 
		closesocket (sock); 
		exit(-1); 
	}

	//send packet
	ret = sendto(sock, (char*)send_buf, packet_size, 0, (SOCKADDR *)&server, sizeof(server));
	if (ret == SOCKET_ERROR){		
        printf("send function failed with error = %d\n", WSAGetLastError());
	}
	else timeout_queue.insert(HeapContainer(timeout, ttl, timeGetTime()));
}

void RecICMP(SOCKET ICMPsock, sockaddr_in server){
	int ret, next_timeout, expected_ttl, expected_timeout;
	int rec_ttl, rtt;
	bool already_found_host = false;
	multiset<HeapContainer>::iterator it;
	WSAEVENT ICMPEvent;
	WSAEVENT DNSEvent;

	//create elements
	SOCKET DNSSocket = CreateDNSSocket();
	sockaddr_in DNSServer = CreateDNSServer();

	u_char rec_buf[MAX_REPLY_SIZE];/* this buffer starts with an IP header */
	IPHeader *router_ip_hdr = (IPHeader *)rec_buf;
	ICMPHeader *router_icmp_hdr = (ICMPHeader *)(router_ip_hdr + 1);
	IPHeader *orig_ip_hdr = (IPHeader *)(router_icmp_hdr + 1);
	ICMPHeader *orig_icmp_hdr = (ICMPHeader *)(orig_ip_hdr + 1);

	//create events
	HANDLE *handles = new HANDLE [2];
	ICMPEvent =  CreateEvent (NULL, false, false, NULL);
	DNSEvent =  CreateEvent (NULL, false, false, NULL);
	handles[0] = ICMPEvent;
	handles[1] = DNSEvent;
	ret = WSAEventSelect(ICMPsock, ICMPEvent, FD_READ);
	if (ret == SOCKET_ERROR){
		printf("WSAEventSelect failed with error = %d\n",WSAGetLastError());
		return;
	}
	ret = WSAEventSelect(DNSSocket, DNSEvent, FD_READ);
	if (ret == SOCKET_ERROR){
		printf("WSAEventSelect failed with error = %d\n",WSAGetLastError());
		return;
	}

	host_hop = 30;	
	while (!timeout_queue.empty()){
		//set up what we are waiting for next
		expected_timeout = timeout_queue.begin()->timeout;
		next_timeout = expected_timeout - timeGetTime();
		if (next_timeout < 0) next_timeout = 0;
		expected_ttl = timeout_queue.begin()->ttl;

		ret = WaitForMultipleObjects(2, handles, false, next_timeout);
		if (ret - WAIT_OBJECT_0 == 0){		
			// ICMP Event
			// receive from the socket into rec_buf			
			ret = recvfrom(ICMPsock, (char*)rec_buf, MAX_REPLY_SIZE, 0, NULL, NULL);
            if (ret == SOCKET_ERROR){
                printf("recv failed with error = %d\n",WSAGetLastError());
                return;
            }
			
			// check if process ID matches
			if (orig_icmp_hdr->id == GetCurrentProcessId()){			

				// check to see if this is TTL_expired or ECHO reply
				if ((router_icmp_hdr->type == ICMP_TTL_EXPIRE || router_icmp_hdr->type == ICMP_ECHO_REPLY)
											&& router_icmp_hdr->code == 0){
					rec_ttl = orig_icmp_hdr->seq;	//received id
					
					if (router_icmp_hdr->type == ICMP_ECHO_REPLY && ret == 28){
						//echo from host
						rec_ttl = router_icmp_hdr->seq;
						if (!already_found_host || rec_ttl < host_hop){
							printf("Echo Reply! Reached host at hop %d", rec_ttl);
							host_hop = rec_ttl;
							already_found_host = true;
						}
					}

					//remove timeout from queue
					for ( it=timeout_queue.begin() ; it != timeout_queue.end(); it++ ){
						if (it->ttl == rec_ttl && !it->typeDNS){
							rtt = timeGetTime() - it->time_sent;
							printf("Found ICMP entry in queue with seq %d ", rec_ttl);
							timeout_queue.erase(it);
							break;
						}
					}
					printf("Hop %d - RTT in %dms\n", rec_ttl, rtt);
					if (rec_ttl <= host_hop){
						//only add and print if before host hop
						if (p[rec_ttl-1].rtt < 0) {
							//first time we get response from this server
							p[rec_ttl-1].rtt = rtt;			
							p[rec_ttl-1].count++;
							// take router_ip_hdr->source_ip and make it in to string IP
							long ip;
							sockaddr_in service;
							ip = router_ip_hdr->source_ip;
							service.sin_addr.s_addr = ip;
							char* ip_string = inet_ntoa(service.sin_addr);
							strcpy_s(p[rec_ttl-1].source_ip, 16, ip_string);
						
							//send DNS and put in timeout
							int pkt_size = SendDNS(DNSSocket, DNSServer, ip_string, rec_ttl);
							int dnsTO = timeGetTime() + 5000;
							HeapContainer h(dnsTO, rec_ttl, timeGetTime());
							h.typeDNS = true;
							timeout_queue.insert(h);
							p[rec_ttl-1].DNS_packet_size = pkt_size;
						}
						else{
							p[rec_ttl-1].count++;
							//calculate avg
							p[rec_ttl-1].rtt = (p[rec_ttl-1].rtt + rtt) / (p[rec_ttl-1].count);
						}
					}
				}
			}
			// else ignore the message
		}
		else if (ret - WAIT_OBJECT_0 == 1){
			//DNS Event
			rec_ttl = RecvDNS(DNSSocket, &p);
			for ( it=timeout_queue.begin() ; it != timeout_queue.end(); it++ ){
				if (it->ttl == rec_ttl && it->typeDNS){
					printf("Found DNS entry in queue with seq %d \n", rec_ttl);
					timeout_queue.erase(it);
					break;
				}
			}
		}
		else { //timeout
			//check if we timed out on DNS or ICMP packet
			if (timeout_queue.begin()->typeDNS){				
				printf("Timed out for DNS or hop %d\n", expected_ttl);
				p[expected_ttl-1].DNS_result = "<DNS Timeout>";
				timeout_queue.erase(timeout_queue.begin());
			}
			else{				
				printf("Timed out for sequence %d\n", expected_ttl);
				timeout_queue.erase(timeout_queue.begin());

				//resend packet for 3 attempts
				if (p[expected_ttl-1].count < 3){
					//calculate new RTO
					int newRTO = DEFAULT_TIMEOUT;
					//if we already have received packets from this router, set new rto to 
					//the earlier time * 2
					if (p[expected_ttl-1].rtt > 0){
						newRTO = p[expected_ttl-1].rtt * 2;
						printf("We have previous RTT for hop %d, set to %d * 2\n", expected_ttl, p[expected_ttl-1].rtt);
					}

					//else, we dont have an RTO for this router
					//if 
					else {
						if (expected_ttl == 30) {
							//this is the last packet, set to last known rtt * 2
							if (p[28].rtt > 0) newRTO = p[28].rtt * 2;
							printf("Last packet timeout, set to old last packet rtt * 2\n");
						}			
						else if (expected_ttl == 1){
							//this is the first packet, rto set to rtt for packet 2
							if (p[1].rtt > 0) newRTO = p[1].rtt;
							printf("First packet timeout, set to next packet rtt\n");
						}
						else if (p[expected_ttl].rtt > 0){
							//we have next packet RTT
							if (p[expected_ttl-2].rtt > 0){
								//and we have old packet RTT
								newRTO = ((p[expected_ttl].rtt + p[expected_ttl-2].rtt) / 2) * 2;
								printf("calculated double of the average of adjacent nodes\n");
							}
						}				
						else newRTO = DEFAULT_TIMEOUT;
					}
					printf("newRTO is %d\n", newRTO);
					
					//send packet and update count
					SendICMP(ICMPsock, server, expected_ttl, newRTO);
					p[expected_ttl-1].count++;
				}
				else{
					p[expected_ttl-1].DNS_result = "<Timed Out>";
					p[expected_ttl-1].rtt = 0;
					strcpy_s(p[expected_ttl-1].source_ip, 16, "");
				}
			}
		}
	}
	closesocket(DNSSocket);
}

void PrintTraceRoute(){
	for ( int i = 0 ; i < host_hop; i++ ){
		printf("#%d %s (%s) | %dms (%d packets)\n", p[i].hop_no, p[i].DNS_result, p[i].source_ip, p[i].rtt, p[i].count);
	}
	if (host_hop == 30)
		printf("Did not reach host in 30 hops!\n");
	printf("Done.\n");
}

// -- UTIL Functions --//
sockaddr_in CreateServer(char* address){
	struct hostent *remote; 
	struct in_addr addr;	
	struct sockaddr_in server;

	///------------------Create Connection Structure--------//////////
	// first assume that the string is an IP address
	DWORD IP = inet_addr (address);
	if (IP == INADDR_NONE)
	{
		// if not a valid IP, then do a DNS lookup
		if ((remote = gethostbyname (address)) == NULL)
		{
			printf ("Invalid string: neither FQDN, nor IP address\n");
			exit(-1);
		}
		else // take the first IP address and copy into sin_addr			
			addr.s_addr = *(u_long *) remote->h_addr;
			printf("Tracerouting to %s...\n", inet_ntoa(addr));
			memcpy ((char *)&(server.sin_addr), remote->h_addr, remote->h_length);
	}
	else
	{
		// if a valid IP, directly drop its binary version into sin_addr
		server.sin_addr.S_un.S_addr = IP;
	}

	// setup the port # and protocol type
	server.sin_family = AF_INET;
	server.sin_port = htons (7);		// host-to-network flips the byte order	

	return server;
}

SOCKET CreateSocket(){
	char name [MAX_NAME]; 
	// get our computer name 
	gethostname (name, MAX_NAME); 
 
	// perform lookup on the name to get IP 
	struct hostent *hp = gethostbyname (name); 
 
	// open socket 
	SOCKET sock = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP); 
	if (sock == INVALID_SOCKET) {
        printf("socket function failed with error = %d\n", WSAGetLastError());
		exit(-1);
	}

	// prepare to bind 
	struct sockaddr_in local; 
	memset(&local, 0, sizeof(struct sockaddr_in)); 

	// copy the first IP; if the host is multi-homed and all interfaces  
	// must be sniffed, you will need multiple sockets 
	memcpy((char *) &(local.sin_addr), hp->h_addr, hp->h_length); 
	local.sin_family = AF_INET; 
	bind (sock, (struct sockaddr*) &local, sizeof (local)); 

	int val = RCVALL_ON;   
	DWORD len;  
	if (WSAIoctl(sock, SIO_RCVALL, &val, sizeof(val), NULL, 0, &len, NULL, NULL) == SOCKET_ERROR){ 
		printf("ioctl failed with %d\n", WSAGetLastError()); 
		exit(-1); 
	}  

	return sock;
}

u_short ip_checksum (u_short * buffer, int size){ 
	u_long cksum = 0; 
  
	/* sum all the words together, adding the final byte if size is odd */ 
	while (size > 1) 
	{ 
		cksum += *buffer++; 
		size -= sizeof (u_short); 
	} 
  
	if (size) 
	cksum += *(u_char *) buffer; 
  
	/* do a little shuffling */ 
	cksum = (cksum >> 16) + (cksum & 0xffff); 
	cksum += (cksum >> 16); 
  
	/* return the bitwise complement of the resulting mishmash */ 
	return (u_short) (~cksum); 
}

SOCKET CreateDNSSocket(){
		// Create a SOCKET for connecting to server
	SOCKET ConnectSocket;
	ConnectSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (ConnectSocket == INVALID_SOCKET) {
		printf("Error at socket(): %ld\n", WSAGetLastError());
		WSACleanup();
		return 0;
	}

	sockaddr_in service;
	service.sin_family = AF_INET;
	service.sin_addr.s_addr = INADDR_ANY;
	service.sin_port = htons(0);
	
	// Bind the socket.
	if (bind( ConnectSocket, (SOCKADDR*) &service, sizeof(service)) == SOCKET_ERROR) {
		printf("bind() failed.\n");
		closesocket(ConnectSocket);
		return 0;
	}

	return ConnectSocket;
}

sockaddr_in CreateDNSServer(){	
	// Set up the RecvAddr structure with the IP address of
	// the receiver and the specified port number.
	sockaddr_in RecvAddr;
	RecvAddr.sin_family = AF_INET;
	RecvAddr.sin_port = htons(53);
	//RecvAddr.sin_addr.s_addr = inet_addr(getDNSServer());
	//RecvAddr.sin_addr.s_addr = inet_addr("8.8.8.8");
	RecvAddr.sin_addr.s_addr = inet_addr("128.194.135.85");

	return RecvAddr;
}
