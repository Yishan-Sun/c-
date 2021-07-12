#include "analysis.h"
#include "sniff.h"

#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>

/*explain in the .h file */
long url_count;
long arp_count;
long syn_count;
long unique_ip;
long *dynamicArray;
int size;
char *readableHead;

void analyse(struct pcap_pkthdr *header,
             const unsigned char *packet,
             int verbose) {
	// TODO your part 2 code here
	
   /*first we entered the Data-link Header*/
   struct ether_header *eth_header = (struct ether_header *) packet;
   unsigned short ether_type = ntohs(eth_header->ether_type);
//   printf("ether type is %hd\n", ether_type); 
   if(ether_type == 2054){   // 2054 is 0x0806 in decimal. which is the arp mode
		arp_count++;		//arp mode, then the arp mode counter ++
   } 
    
   
   /*Second is the Network Header*/
   const unsigned char *ip_pointer = packet + 14; //14 is the unchanging length of ether_header which is 6+6+2 
   struct iphdr *ip_header = (struct iphdr *) ip_pointer;
   
   /*Third is the Transport Header*/
   unsigned char iphdr_length = (unsigned char) 4* (ip_header -> ihl); // ihl in the ip_header store the lendth of whole ip header.
   const unsigned char *tcp_pointer = ip_pointer + iphdr_length;
   struct tcphdr *tcp_header = (struct tcphdr *) tcp_pointer;
   
   unsigned char tcphdr_length = (unsigned char) (tcp_header -> doff);
   unsigned short tcp_destport = ntohs(tcp_header -> dest);
   if (tcp_destport == 80){ // 80 is http port
   		// printf("test in 80\n");  
		/*Method 1 easy way explain in the report */
   		char *httpRequestHead = ( char *)tcp_pointer + tcphdr_length;
		char blacklist_webpage_String[] ="www.google.co.uk";
		if(strstr(httpRequestHead, blacklist_webpage_String) != NULL){   //for strstr(); function, if it is !=NULL, means it contain the webpage
			printf("success in strstr\n");	
			url_count ++;	
		}
		/*method 2, explain in the report */
   		// int length = (*header).len - (14 + iphdr_length + tcphdr_length);

		// readableHead = (char*) malloc(length*sizeof(char));
		
		// int i;
		// for (i = 0; i < length; i++) {
		// 	char byte = (httpRequestHead[i]);
		// 	readableHead[i] = byte;
		// 	printf(" byte %d is %c \n", i, readableHead[i]);
		// }
		// char *pureSentence;
		// pureSentence = strtok(readableHead,"\r\n");
		// char blacklist_webpage_String[] = "Host: www.google.co.uk";
		//  printf("%s\n", pureSentence[0]);
		// while(pureSentence != NULL){
		// 		 printf("%s\n", pureSentence);
		// 		if (strcmp(pureSentence,blacklist_webpage_String) == 0){
		// 			url_count ++;
		// 			return;
		// 		}
		// 		printf("target string AAA is %s\n", blacklist_webpage_String);
		// 		pureSentence = strtok (NULL,"\r\n");
		// }
		

   }
   
   unsigned long ip_saddr = ntohl(ip_header->saddr);  // get the source ipAddress to determine the syn flood attack
   if((tcp_header -> syn) == 1 &&
   		(tcp_header -> urg) == 
		(tcp_header -> ack) == 
		(tcp_header -> psh) == 
		(tcp_header -> rst) == 
		(tcp_header -> fin) == 0)
		{ 
			syn_count ++;
			if (size == 0){  //first time Initialize the dynamically growing array
				size ++;
				dynamicArray = (long*) malloc(size*sizeof(long));  //build a dynamically growing array
				add_ipAddress(dynamicArray, ip_saddr);             //and add every new ip address
				unique_ip ++;       //count for unique source ip ++
			} else{
				if (!contain_ipAddress(dynamicArray, ip_saddr, size)){  //if this ip address is a new unique address
					unique_ip ++;
					size ++;
					add_ipAddress(dynamicArray, ip_saddr);
				}
			} 
		}
}

/*function to check if this ip address already exist */
int contain_ipAddress(long *array, long ipAddress, int length)
{
	int i;
	for(i = 0; i < length; i++){
		if (array[i] == ipAddress) { // if it does contain
			return 1;}
	}
	return 0;  // if it doesn't contain
}

/*add new ip address to the array, then dynamically growing it */
/*Each time a new IP address is added, the realloc function is */
/*used to create a new space based on the size of all the existing ones (including the new one).*/
void add_ipAddress(long *array, long ipAddress) 
{
		long * ptr;
		ptr = (long *)realloc(array, size*sizeof(long));  // realloc to Reassign his pointer address
		array = ptr;
		/*size is start from 1 but array is start from array[0], so size-1 */
		array[size-1] = ipAddress;  
}
