#pragma once

#include "general.hpp"
#include <structures.hpp>

namespace QVPN
{
    namespace Core
    {

        template <typename T>
        concept is_adapter_driver =
            requires(T t) {

                typename T::AdapterList_t;
                typename T::Adapter_t;
                typename T::AdapterHandle_t;
                
                { t.create_adapter() } -> std::same_as<void>;
                { t.capture_adapter() } -> std::same_as<void>;
                { t.close_adapter() } -> std::same_as<void>;
        };

        template <class AdapterDriverImpl>
            requires is_adapter_driver<AdapterDriverImpl>
        class AdapterDriver final : public AdapterDriverImpl
        {


        };


        template <class T>
        concept is_net_driver =
            requires (T t) {
                { t.add_traffic_filter(std::declval<std::string_view>()) } -> std::same_as<void>;
                { t.start_capture_traffic() } -> std::same_as<void>;
                { t.stop_capture_traffic() } -> std::same_as<void>;
        };
        
        template <class NetDriverImpl>
            requires is_net_driver<NetDriverImpl>
        class NetDriver final : public NetDriverImpl
        {

        };



        class IPv4Address final
        {

        public:

            using UByte = Core::DataStructures::UByte;

        private:

            std::array<UByte, 4> ip_{};

        public:

            IPv4Address();
            IPv4Address(UByte first, UByte second, UByte third, UByte four);
            IPv4Address(const IPv4Address& other);
            IPv4Address(IPv4Address&& other);
            IPv4Address& operator=(const IPv4Address& other);
            IPv4Address& operator=(IPv4Address&& other);
            IPv4Address& operator=(const std::array<UByte, 4>& other);
            IPv4Address& operator=(std::array<UByte, 4>&& other);

            UByte operator[](size_t elem);

            std::unique_ptr<std::array<UByte, 4>> to_bytes();

            ~IPv4Address();

            
        };

        template <class Filter>
        concept is_filter =
            requires (Filter f) {

            typename Filter::Filter_t;

            { f.ipv4() } -> std::same_as<typename Filter::Filter_t>;
            { f.ipv6() } -> std::same_as<typename Filter::Filter_t>;
            { f.tcp() } -> std::same_as<typename Filter::Filter_t>;
            { f.udp() } -> std::same_as<typename Filter::Filter_t>;
            { f.source_ipv4(std::declval<const IPv4Address&>()) } -> std::same_as<typename Filter::Filter_t>;
            { f.dest_ipv4(std::declval<const IPv4Address&>()) } -> std::same_as<typename Filter::Filter_t>;
        };

        template <class FilterImpl>
        class TrafficFilter final : public FilterImpl
        {

        };

    }
    
}
