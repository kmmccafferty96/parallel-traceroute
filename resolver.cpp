//Author: Zain Shamsi

#include "dnsclasses.h"

//Starting point for making the request
int SendDNS(SOCKET DNSSocket, sockaddr_in RecvAddr, char* IP, int ttl){
	string hoststring = ReverseIPString(IP);
	char* host = (char*)hoststring.c_str();
	int pkt_size = strlen(host) + 2 + sizeof(fixedDNSheader) + sizeof(queryHeader); 
	char* buf = new char[pkt_size];

	fixedDNSheader *dns_header = (fixedDNSheader *) buf;
	queryHeader *query_header = (queryHeader*) (buf + pkt_size - sizeof(queryHeader));
 
	// fixed field initialization 
	dns_header->ID = htons(ttl);
	dns_header->flags = htons(DNS_QUERY | DNS_RD);
	dns_header->questions = htons(1);
	dns_header->answers = htons(0);
	dns_header->authority = htons(0);
	dns_header->additional = htons(0);
	
	//set query fields
	query_header->qclass = htons(DNS_INET);
	query_header->qtype = htons(DNS_PTR);
 
	//make into 3www6google3com0 format
	MakeDNSQuestion((char*)(dns_header + 1), host); 

	// send request to the server 
	int result = sendto (DNSSocket, buf, pkt_size, 0, (SOCKADDR *)&RecvAddr, sizeof(RecvAddr));
	if (result == SOCKET_ERROR){
		printf("%d error\n",WSAGetLastError());
		return 0;
	}
	//else printf("Sent Request of %d bytes\n", result);

	delete buf; 
	return pkt_size;
}

int RecvDNS(SOCKET DNSSocket, vector<PingResult> *pr){
	char answer[512];   // max DNS packet size 
	int result;

	result = recvfrom (DNSSocket, answer, 512, 0, NULL, NULL); 
	if (result == SOCKET_ERROR){
		printf("%d error\n",WSAGetLastError());
		exit(-1);
	}

	fixedDNSheader *fdh = (fixedDNSheader*)answer; 
	//just read answer field
	int ans_count = ntohs(fdh->answers); 
	int id = ntohs(fdh->ID);	
	if (ans_count == 0){
		(*pr)[id-1].DNS_result = "<No DNS Entry>";		
		return id;
	}
	// skip over variable fields to the answer(s) section 

	int name_length, rdata_length;
	fixedRR *frr;
	char* readptr = answer + (*pr)[id-1].DNS_packet_size; //advance readptr to the answer section

	//loop through each resource record
	for (int i = 0; i < ans_count; i++){				
		name_length = 0;
		char* name = GetName(readptr, answer, &name_length);
		if (name == NULL){
			printf("Jumped too many times in packet\n");
			exit(-1);
		}
		readptr = readptr + name_length; //advance readptr past the name

		frr = (fixedRR*)readptr; 
		rdata_length = ntohs(frr->data_length);
		readptr = readptr + sizeof(*frr); //advance readptr past the resource record		
				
		char* ans_string = new char[rdata_length+1];
		memcpy(ans_string, readptr, rdata_length);
		ans_string[rdata_length] = '\0';
		readptr = readptr + rdata_length; //advance readptr past the rdata

		if (readptr > answer + result){ //sanity check
			printf("Read pointer past packet memory size!\n");
			exit(-1);
		}

		//only care for DNS_PTR records
		if (ntohs(frr->atype) == DNS_PTR){
			(*pr)[id-1].DNS_result = GetName(ans_string, answer, &name_length);
			return id;
		}	
	}
	(*pr)[id-1].DNS_result = "<No DNS Entry>";
	return id;
}

//makes string into 3www6google3com0
void MakeDNSQuestion (char* buf, char* host) { 
	char* token;
	char* context;
	char* delimiters = ".";
	int i = 0;
	int size;
	token = strtok_s(host, delimiters, &context);

	while(token != NULL){ 
		size = strlen(token);
		buf[i++] = size;  //write the size number into ith spot
		memcpy (buf+i, token, size); //write the token into the next <size> spots
		i += size; //keep running counter of where we are in buf

		token = strtok_s(NULL, delimiters, &context);
	} 
	buf[i] = 0; // last word NULL-terminated
}

//unmake string into normal string www.google.com
char* UnMakeDNSQuestion (char* buf) { 
	int i = 0;
	int size;
	char* host = new char[strlen(buf)];
	char* writeptr = host;

	size = buf[0]; //read initial size
	while(size != 0){ 		
		buf = buf + 1; //advance buf to URL part
		memcpy (writeptr, buf, size); //write the token into the next <size> spots
		writeptr = writeptr + size; //advance host pointer to after URL portion
		memcpy (writeptr, ".", 1);	
		buf = buf + size; //advance buf to next size		
		writeptr = writeptr + 1; //advance host pointer
		i += (size + 1); //keep running counter of where we are in buf	
		size = buf[0]; //read next size
	} 
	host[i-1] = '\0'; // remove last dot and NULL-terminate

	return host;
}

//Reverse IP using char*
char* ReverseIP(char* IP){
	char* token;
	char* context;
	char* delimiters = ".";	
	int ip_length = strlen(IP);
	char* tempIP = new char(ip_length);
	strcpy_s(tempIP, ip_length, IP);
	int token_size = 0, i = 0;
	char* rev_IP = new char(ip_length + 15);
	
	
	token = strtok_s(tempIP, delimiters, &context);

	while (token != NULL){
		token_size += strlen(token);
		//write the token to the back of the array
		memcpy(rev_IP + (ip_length - token_size - i), token, strlen(token));
		//write the dot
		if ((token_size + i + 1) <= ip_length) 
			memcpy(rev_IP + (ip_length - token_size - i - 1), ".", 1);	
		//keep track of dots written, so we dont overwrite dots from the back
		i++; 
		token = strtok_s(NULL, delimiters, &context);
	}	
	memcpy(rev_IP + ip_length, ".in-addr.arpa", 13); 
	rev_IP[ip_length + 13] = '\0';
	delete tempIP;
	return rev_IP;
}

//Reverse IP and add ".in-addr.arpa"
string ReverseIPString(char* IP){
	char* token;
	char* context;
	char* delimiters = ".";
	int ip_length = strlen(IP);
	char* tempIP = new char(ip_length+1);
	strcpy_s(tempIP, ip_length+1, IP);
	string ret;
	
	token = strtok_s(tempIP, delimiters, &context);

	while (token != NULL){
		ret = "." + string(token) + ret;
		token = strtok_s(NULL, delimiters, &context);
	}	
	ret.erase(0, 1);
	ret.append(".in-addr.arpa");
	return ret;
}

//create string that may contain offsets, and determine length of name field
char* GetName(char* buffer, char* full_response, int* length){
	int i = 0;
	u_char* readptr = (u_char*)buffer;
	int jumpcount = 0;
	char name[100];

	while (*readptr != 0){
		if (*readptr >= 192){
			if (jumpcount > 5) return NULL; //jumped too many times
			if (jumpcount == 0) *length += 2; //only increment length when we havent jumped
			int offset = (*readptr)* (1 << 8) + *(readptr+1) - (192 << 8);
			readptr = (u_char*)(full_response + offset);
			jumpcount++;
		}
		else{
			if (jumpcount == 0) *length += 1; //only increment length when we havent jumped
			name[i] = *readptr;
			i++;
			readptr += 1;
		}
	}
	name[i] = '\0';
	return UnMakeDNSQuestion(name);
}
