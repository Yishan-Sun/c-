#ifndef CS241_ANALYSIS_H
#define CS241_ANALYSIS_H

#include <pcap.h>

#include <stdio.h>
#include <signal.h>
#include <unistd.h>


/*extern is used to call this value in another file. */
extern long syn_count;       //count for total syn packet
extern long unique_ip;       //count for unique source ip
extern long arp_count;       //count for ARP Cache Poisoning
extern long url_count;       //count for Blacklisted URLs
extern long *dynamicArray;   //dynamically growing array
extern int size;             //size of dynamically growing array 

void analyse(struct pcap_pkthdr *header,
              const unsigned char *packet,
              int verbose);
              
int contain_ipAddress(long *array, long ipAddress, int length);  //function to check if this ip address already exist

void add_ipAddress(long *array, long ipAddress);          // add new ip address to the array, then dynamically growing it

//unsigned char dumpIntoString(const unsigned char *payload, int length);  // *data
#endif
