#include "wireless.h"

bool chk = true;

int main(int argc,char* argv[])
{
    if(argc!=2)
    {
        usage();
        return -1;
    }
    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 100, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }
    airodump(handle,dev);
    pcap_close(handle);
    return 0;
}