#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>		// required by "netfilter.h"
#include <linux/netfilter.h>	// required by NF_ACCEPT, NF_DROP, etc...
#include <libipq.h>		// required by ipq_* functions
#include <arpa/inet.h>		// required by ntoh[s|l]()
#include <signal.h>		// required by SIGINT
#include <string.h>		// required by strerror()

#include <netinet/ip.h>		// required by "struct iph"
#include <netinet/tcp.h>	// required by "struct tcph"
#include <netinet/udp.h>	// required by "struct udph"
#include <netinet/ip_icmp.h>	// required by "struct icmphdr"
#include <netinet/in.h>
#include <netdb.h>

#include <sys/types.h>		// required by "inet_ntop()"
#include <sys/socket.h>		// required by "inet_ntop()"
#include <arpa/inet.h>		// required by "inet_ntop()"

#include "checksum.h"
#define TIMEOUT 5
#define BUF_SIZE 2048
#define DEBUG_MODE_UDP 1
#define MAX 2001
#define tableMAX 2000
#define debugMode 1




uint16_t icmp_checksum(void* vdata,size_t length) {
    // Cast the data pointer to one that can be indexed.
    char* data=(char*)vdata;

    // Initialise the accumulator.
    uint32_t acc=0xffff;

    // Handle complete 16-bit blocks
    size_t i;
    for ( i=0;i+1<length;i+=2) {
        uint16_t word;
        memcpy(&word,data+i,2);
        acc+=ntohs(word);
        if (acc>0xffff) {
            acc-=0xffff;
        }
    }

    // Handle any partial block at the end of the data.
    if (length&1) {
        uint16_t word=0;
        memcpy(&word,data+length-1,1);
        acc+=ntohs(word);
        if (acc>0xffff) {
            acc-=0xffff;
        }
    }

    // Return the checksum in network byte order.
    return htons(~acc);
}

/************************************************************************\
                           Global Variables
\************************************************************************/

typedef struct UDP_NAT_TABLE_TYPE{
	unsigned int ipAddr; //vm b or c
	unsigned short port; 	//vm b or c
	unsigned short translated_port; //vm a
	double timestamp;
	char valid;
}UDP_NAT_TABLE_TYPE;

typedef struct TCP_Table{
	unsigned int originalIP;
	unsigned short originalPort;
	unsigned short newPort;
	int exitFlow;
	int valid;
}TCP_Table;

/*I move them here to make them global variables*/
struct iphdr *ip; 
unsigned char buf[BUF_SIZE];	// buffer to stored queued packets
ipq_packet_msg_t *msg;		// point to the packet info.
unsigned int public_IP;
unsigned int LOCAL_NETWORK;
unsigned int  LOCAL_MASK;

char PORTARRY[2001];
int decision;
UDP_NAT_TABLE_TYPE UDP_NAT_TABLE[MAX];
TCP_Table currentTable[tableMAX];

struct tcphdr *tcph;
 struct ipq_handle *ipq_handle = NULL;	// The IPQ handle
unsigned int pkt_count = 0;		// Count the number of queued packets

// check if port opened
int checkPortOpen(unsigned short checkingPort){
	// connect to server 
	int connectServerSocket;
	struct sockaddr_in serverAddr;

 	connectServerSocket = socket(AF_INET,SOCK_STREAM,0);
 	memset(&serverAddr,0,sizeof(serverAddr));
 	serverAddr.sin_family = AF_INET;
 	serverAddr.sin_addr.s_addr = inet_addr("10.4.17.1");
 	serverAddr.sin_port = htons(checkingPort);
 	int serverAddrLength;
 	serverAddrLength = sizeof(serverAddr);
 	if(connect(connectServerSocket,(struct sockaddr *) &serverAddr, serverAddrLength)<0){
 		printf("Port %d is closed!\n",checkingPort);
 		fflush(stdout);
 		close(connectServerSocket);
 		return -1;
 	}else{
 		printf("Port %d is opened!\n",checkingPort);
 		close(connectServerSocket);
 		return 1;
 	}
 	return 1;
}

unsigned short new_checksum(unsigned short *buffer, int size)
{
 unsigned long cksum=0;
 while(size >1) {
  cksum+=*buffer++;
  size-=sizeof(unsigned short);
 }
 if(size) cksum+=*(unsigned short*)buffer;
 cksum=(cksum >> 16)+(cksum&0xffff);
 cksum+=(cksum >>16);
 return (unsigned short)(~cksum);
}


/************************************************************************\
                           TCP Part
\************************************************************************/

void checkTermination(int foundEntry){
	if(tcph->fin == 1){
		if(currentTable[foundEntry].exitFlow == -1){
			currentTable[foundEntry].exitFlow = 1;
			if(debugMode){
				printf("FIN sent to initiate closing..\n");
			}
		}else if(currentTable[foundEntry].exitFlow == 1){
			currentTable[foundEntry].exitFlow = 2;
			if(debugMode){
				printf("FIN sent to respond to closing..\n");
			}
		}else{
			if(debugMode){
				printf("FIN sent Error!\n");
			}
		}
		return;
	}

	if(tcph->ack == 1 && tcph->fin != 1){
		if(currentTable[foundEntry].exitFlow == 2){
			currentTable[foundEntry].valid = 0;
			int index=currentTable[foundEntry].newPort-10000;/*modify here*/
				currentTable[foundEntry].exitFlow = -1;
				PORTARRY[index]=0;/*modify here*/
			if(debugMode){
				printf("The final ACK received and thus terminate this TCP flow!\n");
				
			}
		}
	}
}

int handle_tcp(){
	unsigned char *ip_pkt = msg->payload;
	struct iphdr *ip;
	int i;
	int foundEntry;
	int insertEntry;
	int newPort = -1;
	struct in_addr container;

	ip = (struct iphdr *) ip_pkt;
	tcph = (struct tcphdr *) (((unsigned char *) ip) + ip->ihl * 4);

	struct in_addr sip, dip;
	char sip_str[INET_ADDRSTRLEN+1], dip_str[INET_ADDRSTRLEN+1];

	sip.s_addr = ip->saddr;
	dip.s_addr = ip->daddr;

	if(!inet_ntop(AF_INET, &sip, sip_str, INET_ADDRSTRLEN))
	{
		printf("Impossible: error in source IP\n");
		return -1;
	}

	if(!inet_ntop(AF_INET, &dip, dip_str, INET_ADDRSTRLEN))
	{
		printf("Impossible: error in destination IP\n");
		return -1;
	}

	if((ntohl(ip->saddr) & LOCAL_MASK)==(LOCAL_NETWORK & LOCAL_MASK)){
		// out-bound packet
		container.s_addr = ip->saddr;
		printf("This is out-bound TCP packet. Source IP: %s, Source Port: %d\n",inet_ntoa(container),tcph->source);

		foundEntry = -1;

		for(i=0;i<tableMAX;i++){
			if(currentTable[i].valid == 1){
				if((currentTable[i].originalIP == (ntohl(ip->saddr))) && (currentTable[i].originalPort == (ntohs(tcph->source)))){
					foundEntry = i;
					break;
				}
			}
		}

		if(foundEntry == -1){
			if(tcph->syn == 1){
				if(debugMode == 1){
					printf("Received a SYN packet && Not found in Table Entry\n");
				}

				newPort = -1;
				for(i=0;i<2001;i++){
					// if(checkPortOpen((i+10000))==-1){
					// PORTARRY[i]=1;
					// }
					if(PORTARRY[i] == 0){
							PORTARRY[i]=1;	/*modify here*/
							newPort = (i+10000); 
							break; 	/*modify here*/
					}
				}

				if(newPort == -1){
					printf("No new Port available!\n");
					return -1;
				}else{
					insertEntry = -1;
					for(i=0;i<tableMAX;i++){
						if(currentTable[i].valid == 0){
							insertEntry = i;
							break;  /*modify here*/
						}
					}

					if(insertEntry == -1){
						printf("Warning! There is no empty entry to be inserted!!\n");
						return -1;
					}else{
						currentTable[insertEntry].originalIP = ntohl(ip->saddr);
						currentTable[insertEntry].originalPort = ntohs(tcph->source);
						currentTable[insertEntry].newPort = newPort;
						currentTable[insertEntry].exitFlow = -1;
						currentTable[insertEntry].valid = 1;

						if(debugMode){
							printf("Created new Entry table! NewPort: %d\n",newPort);
						}
						ip->saddr = htonl(public_IP);
						tcph->source = htons(currentTable[insertEntry].newPort);

						ip->check = (ip_checksum(msg->payload));
						tcph->check = (tcp_checksum(msg->payload));

						return 1;
					}
				}
			}else{
				if(debugMode){
					printf("Received Not a SYN packet && Not found in Table Entry\n");
					printf("Drop the packer!\n");
				}
				return -1;
			}
		}else{
			if(tcph->syn == 1){
				if(debugMode){
					printf("Warning!! Received a SYN packet && found in Table Entry, impossible! Dropped!\n");
				}
				ip->saddr = htonl(public_IP);
				tcph->source = htons(currentTable[foundEntry].newPort);

				ip->check = (ip_checksum(msg->payload));
				tcph->check = (tcp_checksum(msg->payload));

				checkTermination(foundEntry);
				return 1;
			}else{
				if(debugMode){
					printf("Received Not a SYN packet && found in Table Entry\n");
				}
				ip->saddr = htonl(public_IP);
				tcph->source = htons(currentTable[foundEntry].newPort);

				ip->check = (ip_checksum(msg->payload));
				tcph->check = (tcp_checksum(msg->payload));

				if(debugMode){
					printf("TCP IP address and Port Modified as retrieved from table= Port: %d \n",ntohs(tcph->source));
				}

				checkTermination(foundEntry);
				
				return 1;
			}
		}
	}else{
		// in-bound packet
			container.s_addr = ip->saddr;
		printf("This is in-bound TCP packet. Source IP: %s, Source Port: %d\n",inet_ntoa(container),tcph->source);


		foundEntry = -1;
		for(i=0;i<tableMAX;i++){
			if(currentTable[i].valid == 1){
				if(currentTable[i].newPort == (ntohs(tcph->dest))){
					foundEntry = i;
					break;
				}
			}
		}

		if(foundEntry == -1){
			if(debugMode == 1){
					printf("Dropped TCP in-bound packet because no entry found!\n");
			}
			return -1;
		}else{
			ip->daddr = htonl(currentTable[foundEntry].originalIP);
			tcph->dest = htons(currentTable[foundEntry].originalPort);
			ip->check = (ip_checksum(msg->payload));
			tcph->check = (tcp_checksum(msg->payload));

			if(debugMode){
					printf("Entry found! Modified in-bound packet!\n");
			}

			checkTermination(foundEntry);

			if(tcph->rst == 1){
				if(debugMode){
					printf("The in-bound packet is a RST packet, translated done but dropped the entry\n");
				}
				currentTable[foundEntry].valid = 0;
			}

			return 1;
		}
	}
}




/************************************************************************\
                           UDP Part
\************************************************************************/


void check_udp_entry_time_out() 
{
		// struct udphdr * udph = ( struct udphdr *) ((( char *) ip )
		// + ip ->ihl *4) ;

		// unsigned int ip_temp=0;
		//  unsigned short port_temp=0;	


			if (( ntohl (ip -> saddr ) & LOCAL_MASK )== (LOCAL_NETWORK & LOCAL_MASK) ) 
			{

			 if(DEBUG_MODE_UDP)printf("Out-bound CHECK Timestamp \n");	fflush(stdout);
				//out
					// ip_temp=ntohl(ip -> saddr);//can i?
					// port_temp=ntohs(udph -> source);//can i?

					double ts = msg -> timestamp_sec +( double )msg -> timestamp_usec/1000000;

					int i;
					for(i=0;i<MAX;i++)
					{
						
						// if(DEBUG_MODE_UDP) printf("UDP out-bound CHECK LOOP\n");	fflush(stdout);

						// if((ip_temp==UDP_NAT_TABLE[i].ipAddr)&&(port_temp==UDP_NAT_TABLE[i].port)&&(UDP_NAT_TABLE[i].valid==1))
						// {
						// if(DEBUG_MODE_UDP) printf("UDP out-bound CHECK Match\n");	fflush(stdout);
						double time_difference=100;
						time_difference=ts-UDP_NAT_TABLE[i].timestamp;

							if((time_difference>TIMEOUT)&&(UDP_NAT_TABLE[i].valid==1))
							{
								UDP_NAT_TABLE[i].valid=0;
								int index;
								index=UDP_NAT_TABLE[i].translated_port-10000;
								PORTARRY[index]=0;
							struct in_addr temp_inf;
								temp_inf.s_addr=htonl(UDP_NAT_TABLE[i].ipAddr);
								if(DEBUG_MODE_UDP) printf("****UDP NAT ENTRY expired,ip: %s port: %d translated_port %d ****\n",(char *)inet_ntoa(temp_inf),UDP_NAT_TABLE[i].port,UDP_NAT_TABLE[i].translated_port);	fflush(stdout);
							}
						


						// }

						// 	break;
					}
			
					// if(DEBUG_MODE_UDP) printf("After UDP out-bound CHECK \n");	fflush(stdout);


			}

			else 
			{
				// in
				 if(DEBUG_MODE_UDP)printf("In-bound CHECK Timestamp \n");	fflush(stdout);

				// if(DEBUG_MODE_UDP) printf("UDP in-bound CHECK \n");	fflush(stdout);
						// port_temp=ntohs(udph -> dest);//can i?

					int i;
					for(i=0;i<MAX;i++)
					{
						// if(DEBUG_MODE_UDP) printf("UDP IN-bound CHECK LOOP\n");	fflush(stdout);


						// if((port_temp==UDP_NAT_TABLE[i].translated_port)&&(UDP_NAT_TABLE[i].valid==1))
						// {
						// if(DEBUG_MODE_UDP) printf("UDP IN-bound CHECK Match\n"); fflush(stdout);

						double ts = msg ->timestamp_sec +( double )msg ->timestamp_usec /1000000;
						double time_difference=100;
						time_difference=ts-UDP_NAT_TABLE[i].timestamp;

							if((time_difference>TIMEOUT)&&(UDP_NAT_TABLE[i].valid==1))
							{
								UDP_NAT_TABLE[i].valid=0;
								int index;
								index=UDP_NAT_TABLE[i].translated_port-10000;
								PORTARRY[index]=0;
								struct in_addr temp_inf;
								temp_inf.s_addr=htonl(UDP_NAT_TABLE[i].ipAddr);
								if(DEBUG_MODE_UDP) printf("****UDP NAT ENTRY expired,ip: %s port: %d translated_port: %d ****\n",(char *)inet_ntoa(temp_inf),UDP_NAT_TABLE[i].port,UDP_NAT_TABLE[i].translated_port);	fflush(stdout);
							}
						// 	break;
						// }
					}
					// if(DEBUG_MODE_UDP) printf("After UDP in-bound CHECK \n");		fflush(stdout);


			}
			
	

}


int UDP_Handling(){

int change=2;

struct udphdr * udph = ( struct udphdr *) ((( char *) ip )
		+ ip ->ihl *4) ;


if (( ntohl (ip -> saddr ) & LOCAL_MASK )== (LOCAL_NETWORK & LOCAL_MASK) ) {
// Out-bound traffic



/*step1:  search if the incoming packet has a source IP-port pair*/

		



		int match=0;
		int match_index=0;
		unsigned int ip_temp=0;
		unsigned short port_temp=0;
		ip_temp=ntohl(ip -> saddr);//can i?
		port_temp=ntohs(udph -> source);//can i?

		struct in_addr temp_inf;
		temp_inf.s_addr=ip->saddr;
		if(DEBUG_MODE_UDP) printf("UDP out-bound traffic form ip:%s port:%d\n",(char *)inet_ntoa(temp_inf),port_temp);	
		fflush(stdout);

		int i;
		for(i=0;i<MAX;i++)
		{
			if((ip_temp==UDP_NAT_TABLE[i].ipAddr)&&(port_temp==UDP_NAT_TABLE[i].port)&&(UDP_NAT_TABLE[i].valid==1))
				{
					match=1;
					match_index=i;
					break;
					if(DEBUG_MODE_UDP) printf("After UDP out-bound match_index: %d \n",match_index);		fflush(stdout);
				}
		}


/*step2: If yes, the NAT program should use the previously-assigned translated port number for the outbound packet.*/
		if(match)
		{
			if(DEBUG_MODE_UDP) printf("UDP out-bound MATCH \n");		fflush(stdout);


			/*step4:update information.*/
			// now translate and update header
		port_temp=UDP_NAT_TABLE[match_index].translated_port;
		if(DEBUG_MODE_UDP) printf("UDP out-bound translate to port:  %d\n",UDP_NAT_TABLE[match_index].translated_port);		fflush(stdout);

		port_temp=htons(port_temp);
		udph -> source=port_temp;

		ip -> saddr=htonl(public_IP);

		udph -> check=(udp_checksum(msg->payload));
		ip -> check=(ip_checksum(msg->payload));

		//refresh timestamp
		double ts = msg -> timestamp_sec +( double )msg -> timestamp_usec/1000000;

			UDP_NAT_TABLE[match_index].timestamp=ts;//need modify
		


			change=1;
			return change;
		}//end if yes

/*step3: If not, the NAT program should create new entry.*/

		else
		{

			if(DEBUG_MODE_UDP) printf("UDP out-bound Doesn't MATCH \n");		fflush(stdout);


			ip_temp=ntohl(ip -> saddr);//can i?  vm b or c 
			port_temp=ntohs(udph -> source);//can i? vm b or c 

			
			unsigned short translated_port_temp=0;

			int i;
			for(i=0;i<2001;i++)
			{
				// if(checkPortOpen((i+10000))==-1){
				// 	PORTARRY[i]=1;
				// }
				if(PORTARRY[i]==0)
				{
					PORTARRY[i]=1;
					translated_port_temp=10000+i;
					break;
				}

			}

			if(translated_port_temp==0)
			{
				printf("No available port!!!\n");
				return -1;

			}

			// if(DEBUG_MODE_UDP)
			// 	printf("Translated_port_temp is  %u\n", translated_port_temp);	fflush(stdout);



			if((translated_port_temp<=12000)&&(10000<=translated_port_temp))
			{

					int i;
					for(i=0;i<MAX;i++)
					{
							if(UDP_NAT_TABLE[i].valid==0)
							{
								break;
							}	

						}

						if(i==MAX)
						{

							printf("No available NAT entry!!!\n");
							return -1;
						}
		if(DEBUG_MODE_UDP) printf("UDP out-bound Create new entry: translated_port %d\n",translated_port_temp);		fflush(stdout);
		if(DEBUG_MODE_UDP) printf("UDP out-bound translate to port:  %d\n",translated_port_temp);		fflush(stdout);


			UDP_NAT_TABLE[i].ipAddr=ip_temp;
			UDP_NAT_TABLE[i].port=port_temp;
			UDP_NAT_TABLE[i].translated_port=translated_port_temp;
			UDP_NAT_TABLE[i].valid=1;


			double ts = msg -> timestamp_sec +( double )msg -> timestamp_usec /1000000;

			UDP_NAT_TABLE[i].timestamp=ts;//need modify

			
			/*step4:update information.*/

			// now translate and update header
			port_temp=UDP_NAT_TABLE[i].translated_port;
			port_temp=htons(port_temp);
			udph -> source=port_temp;

			
			ip -> saddr=htonl(public_IP);



			
			udph -> check=(udp_checksum(msg->payload));
			ip -> check=(ip_checksum(msg->payload));
			

			change=1;
			return change;
			}
			else
			{

			printf("port number %d out of range\n", translated_port_temp);
			change=-1;
			return change;

			}





		}//end if not
	}else {
// In-bound traffic
		unsigned short port_temp=0;
		port_temp=ntohs(udph -> source);
		
		struct in_addr temp_inf;
		temp_inf.s_addr=ip->saddr;
		if(DEBUG_MODE_UDP) printf("UDP in-bound traffic form ip:%s port:%d\n",(char *)inet_ntoa(temp_inf),port_temp);	
		fflush(stdout);
		int match=0;
		int match_index=0;
		unsigned int ip_temp=0;
		
		port_temp=ntohs(udph -> dest);//can i?
		int i;
		for(i=0;i<MAX;i++)
		{
			if((port_temp==UDP_NAT_TABLE[i].translated_port)&&(UDP_NAT_TABLE[i].valid==1))
				{
					match=1;
					match_index=i;
					break;
				}
		}


		if(match)
		{
		if(DEBUG_MODE_UDP) printf("UDP in-bound MATCH \n");		fflush(stdout);


			/*step4:update information.*/
			// now translate and update header
		port_temp=UDP_NAT_TABLE[match_index].port;
		port_temp=htons(port_temp);
		udph -> dest=port_temp;
		if(DEBUG_MODE_UDP) printf("UDP out-bound  translate port from  %d  to   %d\n",UDP_NAT_TABLE[match_index].translated_port, UDP_NAT_TABLE[match_index].port);		fflush(stdout);


		ip_temp=UDP_NAT_TABLE[match_index].ipAddr;
		ip_temp=htonl(ip_temp);
		ip -> daddr=ip_temp;

		udph -> check=(udp_checksum(msg->payload));
		ip -> check=(ip_checksum(msg->payload));

		//refresh timestamp
		double ts = msg -> timestamp_sec +( double )msg -> timestamp_usec /1000000;

			UDP_NAT_TABLE[match_index].timestamp=ts;//need modify
	


			change=1;
			return change;
		}//end if yes
		else
		{
			if(DEBUG_MODE_UDP) printf("UDP in-bound NOT MATCH \n");		fflush(stdout);
			change=-1;
			return change;
		}


}





return change;

}




int ICMP_Handling()
{
		struct icmphdr * icmp=(struct icmphdr *)(((unsigned char *) ip) + ip->ihl * 4);

		unsigned int type=icmp->type;
		unsigned int code=icmp->code;
		unsigned short port_temp=0;
		unsigned int ip_temp=0;
		int change=2;
		if((type==3)&&(code==3))
		{

				if(DEBUG_MODE_UDP) printf("Unreachable Port \n");		fflush(stdout);
					
					memcpy(&port_temp,&msg->payload[48],sizeof(port_temp));
					port_temp=ntohs(port_temp);

					printf("Source port %d\n", port_temp);
			/*	int i=0;
				
				for(i=0;i<72;i++){
					printf("%d:%d \n ",i,msg->payload[i]);
				}
			*/
			int match=0;
			int match_index=0;
			int i;
				for(i=0;i<MAX;i++)
				{
					if((port_temp==UDP_NAT_TABLE[i].translated_port)&&(UDP_NAT_TABLE[i].valid==1))
						{
							match=1;
							match_index=i;
							break;
						}
				}


				if(match)
				{
				// if(DEBUG_MODE_UDP) printf("UDP in-bound MATCH \n");		fflush(stdout);


					/*step4:update information.*/
					// now translate and update header
				port_temp=UDP_NAT_TABLE[match_index].port;
				port_temp=htons(port_temp);
				memcpy(&msg->payload[48],&port_temp,sizeof(port_temp));
				
				// if(DEBUG_MODE_UDP) printf("UDP out-bound  translate port from  %d  to   %d\n",UDP_NAT_TABLE[match_index].translated_port, UDP_NAT_TABLE[match_index].port);		fflush(stdout);


				ip_temp=UDP_NAT_TABLE[match_index].ipAddr;
				ip_temp=htonl(ip_temp);
				ip -> daddr=ip_temp;

				// udph -> check=(udp_checksum(msg->payload));
				ip -> check=(ip_checksum(msg->payload));
				icmp->checksum = 0;
				for(i=0;i<55;i++){
					printf("Num: %d: %d\n",i,msg->payload[i]);
				}
				
				icmp->checksum=checksum(&msg->payload[20],38);
			
				// hihi

				//refresh timestamp
				double ts = msg -> timestamp_sec +( double )msg -> timestamp_usec /1000000;

					UDP_NAT_TABLE[match_index].timestamp=ts;//need modify
			


					change=1;
					return change;
				}//end if yes
				else
				{
					if(DEBUG_MODE_UDP) printf("UDP in-bound NOT MATCH \n");		fflush(stdout);
					change=-1;
					return change;
				}


		}
		return change;
}















void byebye(char *msg) {
	if(ipq_handle)
		ipq_destroy_handle(ipq_handle);

	system("/sbin/iptables -F");
	printf("\n  iptables flushed.\n");

	if(msg != NULL) {		// I have something to say.
		printf("Number of processed packets: %u\n", pkt_count);
		ipq_perror(msg);
		exit(1);
	}
	else {			// I have nothing to say.
		printf("  Number of processed packets: %u\n", pkt_count);
		puts("  Goodbye.");
		exit(0);
	}
}

void sig_handler(int sig) {
	if(sig == SIGINT)
		byebye(NULL);
}

void do_your_job(unsigned char *ip_pkt)
{
	pkt_count++;

	printf("[%5d] ", pkt_count);

	ip = (struct iphdr *) ip_pkt;
	check_udp_entry_time_out();

	switch(ip->protocol)
	{
	  case IPPROTO_TCP:
		printf("Received a TCP packet\n");
	  	decision=handle_tcp();
		break;

	  case IPPROTO_UDP:
		printf("Received a UDP packet\n");
		decision=UDP_Handling();
		break;

	  case IPPROTO_ICMP:
		printf("This is ICMP packet\n");
		decision=ICMP_Handling();

		break;

	  default:
		printf("Unsupported protocol\n");
	}

} 


int main(int argc, char **argv)
{
	unsigned int tempMask;
	struct in_addr container;
	if(argc!=4)
	{
		printf("Usage: ./nat [public IP] [internal IP] [netmask] \n");
		exit(0);
	}
	else
	{

		inet_aton(argv[1],&container);
		public_IP = ntohl(container.s_addr);
                inet_aton(argv[2],&container);
		LOCAL_NETWORK=ntohl(container.s_addr);

		LOCAL_MASK = 0xFFFFFFFF;
		tempMask = atoi(argv[3]);
		LOCAL_MASK = LOCAL_MASK << (32 - tempMask);
	}
	
	memset(PORTARRY,0,sizeof(char)*2001);


// initialize 
		int i;
		for(i=0;i<MAX;i++)
		{
			//currentTable[i].valid = 0;
			UDP_NAT_TABLE[i].valid = 0;
		}

  /**** Create the ipq_handle ****/

	if( (ipq_handle = ipq_create_handle(0, PF_INET)) == NULL)
	{
		byebye("ipq_create_handle");	// exit(1) included.
	}

  /**** ipq_set_mode: I want the entire packet ****/

	if(ipq_set_mode(ipq_handle, IPQ_COPY_PACKET, BUF_SIZE) == -1)
	{
		byebye("ipq_set_mode");	// exit(1) included.
	}

	signal(SIGINT, sig_handler);	// Handle Ctrl + C.

	printf("Program: %s is ready\n", argv[0]);

	do
	{
	  /**** Read the packet from the QUEUE ****/

		if(ipq_read(ipq_handle, buf, BUF_SIZE, 0) == -1)
			byebye("ipq_read");	// exit(1) included

	  /**** Check whether it is an error or not ****/

		if(ipq_message_type(buf) == NLMSG_ERROR)
		{
			fprintf(stderr,
				"Error - ipq_message_type(): %s (errno = %d).\n",
				strerror(ipq_get_msgerr(buf)),
				ipq_get_msgerr(buf));
			exit(1);
		}

	  /**** This is the way to read the packet content ****/

		msg = ipq_get_packet(buf);
		
	

		do_your_job(msg->payload);
		 


		  
		if(decision == -1){

				  printf("Decision: Drop\n");

			if(ipq_set_verdict(ipq_handle, msg->packet_id, NF_DROP, 0, NULL) == -1)
			{
		
			byebye("ipq_set_verdict");	// exit(1) included.

			}
		}else if(decision == 1){
			 printf("Decision: Modify\n");

			if(ipq_set_verdict(ipq_handle, msg->packet_id, NF_ACCEPT, msg->data_len, msg->payload) == -1)
			{
			byebye("ipq_set_verdict");	// exit(1) included.
			}
		}else{
			 printf("Decision: Unchanged\n");

			if(ipq_set_verdict(ipq_handle, msg->packet_id, NF_ACCEPT, 0, NULL) == -1)
			{
			byebye("ipq_set_verdict");	// exit(1) included.
			}
		}

	}while(1);

	return 0;
}
