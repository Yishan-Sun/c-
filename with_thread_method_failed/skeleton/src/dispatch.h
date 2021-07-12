#ifndef CS241_DISPATCH_H
#define CS241_DISPATCH_H

#include <pcap.h>

void dispatch(struct pcap_pkthdr *header, 
              const unsigned char *packet,
              int verbose);

struct thread_args{
    struct pcap_pkthdr *header;
    const unsigned char *packet;
    int verbose;
}

#endif
