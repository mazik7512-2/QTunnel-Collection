#pragma once

#include <qvpn_lib.hpp>


namespace QVPN {

    namespace NetTools {

        using UByte = QVPN::Core::BaseTypes::UByte;
        using UShort = QVPN::Core::BaseTypes::UShort;
        using UInt = QVPN::Core::BaseTypes::UInt;
        using NetAddr = QVPN::Core::NetAddr;
        using NetProtocol = QVPN::Core::NetProtocol;
        using TransportProtocol = QVPN::Core::TransportProtocol;



        namespace details {

#ifdef _MSC_VER
#define PACKED_STRUCT(declaration) \
        __pragma(pack(push, 1)) declaration __pragma(pack(pop))
#else
#define PACKED_STRUCT(declaration) \
        declaration __attribute__((packed))
#endif

            // Должен совпадать с bpf_filter.c
            PACKED_STRUCT(
            struct filter_key {

                UByte net_proto;
                UByte transport_proto;

                UInt src_ip;
                UShort src_port;

                UInt dst_ip;
                UShort dst_port;

            });

#undef PACKED_STRUCT
        }


        class QVPN_SocketFilter
        {
        private:
            details::filter_key filter_;

        public:

            using SocketFilter_t = details::filter_key;

            QVPN_SocketFilter(const QVPN::Core::QVPNSocketData& s_data);
            QVPN_SocketFilter(const QVPN::Core::QVPNServerSocketData& s_data);

            void ipv4();
            void ipv6();
            void net_ver(UByte net);

            void src(const NetAddr& addr);
            void dst(const NetAddr& addr);

            void src_port(UShort port);
            void dst_port(UShort port);

            void tcp();
            void udp();

            void custom_protocol(UByte proto);

            SocketFilter_t& get_filters();

        };

    }

}



