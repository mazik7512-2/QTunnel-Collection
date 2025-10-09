#pragma once
#include <pcap.h>
#include "general.hpp"
#include <structures.hpp>
#include "Packet32.h"
#include "iphlpapi.h"
#include <lib.hpp>

#pragma comment(lib, "IPHLPAPI.lib")

namespace QVPN
{
    namespace PcapExt
    {

        class PcapNetDriver
        {
        public:

            using AdapterHandle_t = pcap_if_t;
            using Adapter_t = QVPN::Core::DataStructures::Adapter<AdapterHandle_t>;
            using AdapterList_t = QVPN::Core::DataStructures::AdapterList<AdapterHandle_t>;

            std::unique_ptr<AdapterList_t> get_adapters_list() const;
            void capture_adapter(std::string_view adapter);
            void capture_adapter(Adapter_t& adapter);

            //static QVPN::Core::DataStructures::Adapter convert_from_pcap_adapter(const IP_ADAPTER_ADDRESSES& adapter);
            static Adapter_t convert_from_pcap_adapter(const pcap_if_t* adapter);

        };

        template <class AdapterHandle>
        class AdapterCriteria final {
        public:

            static bool check_criteria(const PcapNetDriver::Adapter_t& adapter);
        };


    }

    
}