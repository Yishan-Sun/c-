#include "dispatch.h"
#include "analysis.h"

#include <pcap.h>
#include <pthread.h>


void dispatch(struct pcap_pkthdr *header,
              const unsigned char *packet,
              int verbose) {
  // TODO: Your part 2 code here
  // This method should handle dispatching of work to threads. At present
  // it is a simple passthrough as this skeleton is single-threaded.
  
  analyse(header, packet, verbose);
}
