#include "filter.h"

Filters::Filters(){

}

Filters::~Filters(){

}

void Filters::netmask_lookup(const std::string& device, char* error) {
    if (pcap_lookupnet(device.c_str(), &net, &mask, error) == -1) {
        std::cerr << "pcap_lookupnet() failed: " << error << std::endl;
        net = 0;
        mask = 0;
    }
}

void Filters::filter_processing(pcap_t *handle, const char *filter_exp, int optimize, bpf_u_int32 netmask) {
    if (pcap_compile(handle, &fp, filter_exp, optimize, netmask) == -1) {
        std::cerr << "pcap_compile() failed: " << pcap_geterr(handle) << std::endl;
        return;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "pcap_setfilter() failed: " << pcap_geterr(handle) << std::endl;
        return;
    }
}

bpf_u_int32 Filters::get_net(){
    return net;
}

bpf_u_int32 Filters::get_mask()
{
    return mask;
}
