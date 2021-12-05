#pragma once

#include <iostream>
#include <cstdio>
#include <utility>
#include <map>
#include <string>
#include <ctype.h>
#include <signal.h>
#include <pcap.h>
#include "802-11.h"

extern bool chk;
using std::map;
using std::string;
using std::pair;

void usage()
{
    puts("syntax : airodump <interface>\nsample : airodump mon0");
}

void print_info(map<Mac,pair<uint64_t,string>>& info)
{
    printf("\x1b[H\x1b[J");
    puts("-------------------");
    printf("BSSID\t\t    BEACONS\tESSID\n");
    auto iter = info.begin();
    while(iter!=info.end())
    {
        std::cout << string(iter->first) << '\t' << (iter->second).first << '\t' << (iter->second).second << std::endl;
        ++iter;
    }
    puts("-------------------");
}

bool check_essid(string& essid)
{
    for(char c : essid) if(isprint(c) == 0) return false;
    return true;
}

void sigint_handler(int signo)
{
    chk = false;
    putchar('\n');
}

void airodump(pcap_t *handle,char* dev)
{
    signal(SIGINT,sigint_handler);
    struct pcap_pkthdr* header;
    const u_char* packet;
    map<Mac,pair<uint64_t,string>> info;

    while(chk)
    {
        int res = pcap_next_ex(handle,&header,&packet);
        if(res == 0) continue;
        
        if(res == -1 || res == -2)
        {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        PRTHDR radiotap = (PRTHDR)packet;
        uint16_t radio_len = radiotap->hdr_len;
        PBF beacon = (PBF)(packet+radio_len);

        if(beacon->subtype != BEACON) continue;
        
        Mac bssid = beacon->bssid;
        PFMF fixed_man = (PFMF)(((u_char*)beacon)+sizeof(BF));
        char* tagged = ((char*)fixed_man)+sizeof(FMF);
        uint8_t essid_len = *(tagged+1);
        string essid = string(tagged+2,essid_len);
        auto iter = info.find(bssid);

        if(iter == info.end())
        {
            bool isPrintable = check_essid(essid);
            pair<uint64_t,string> tmp;
            if(isPrintable) tmp = {1,essid};
            else tmp = {0,string("<length : ")+std::to_string(essid_len)+string(">")};
            info[bssid] = tmp;
        }
        else ++(iter->second).first;

        print_info(info);
    }
}