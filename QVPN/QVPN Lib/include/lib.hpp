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
            std::string to_string();

            ~IPv4Address();

            
        };


        template <class Filter>
        concept is_filter_type =
            requires (Filter f, typename Filter::Convertable_to c_t) {

            typename Filter::Convertable_to;
            typename Filter::Convertable_from;

            { f.operator&&(std::declval<const Filter&>()) } -> std::same_as<Filter&>;
            { Filter(c_t) };
            { f.operator Filter::Convertable_to() };
        };


        template <class Filter>
        concept is_filter =
            requires (Filter f) {

            typename Filter::Filter_t;

            { f.ipv4() } -> std::same_as<typename Filter::Filter_t>;
            { f.ipv6() } -> std::same_as<typename Filter::Filter_t>;
            { f.tcp() } -> std::same_as<typename Filter::Filter_t>;
            { f.udp() } -> std::same_as<typename Filter::Filter_t>;
            { f.source(std::declval<const IPv4Address&>()) } -> std::same_as<typename Filter::Filter_t>;
            { f.dest(std::declval<const IPv4Address&>()) } -> std::same_as<typename Filter::Filter_t>;
            { f.tcp_source_port(std::declval<unsigned int>()) } -> std::same_as<typename Filter::Filter_t>;
            { f.tcp_dest_port(std::declval<unsigned int>()) } -> std::same_as<typename Filter::Filter_t>;
            { f.udp_source_port(std::declval<unsigned int>()) } -> std::same_as<typename Filter::Filter_t>;
            { f.udp_dest_port(std::declval<unsigned int>()) } -> std::same_as<typename Filter::Filter_t>;
            { f.source_port(std::declval<unsigned int>()) } -> std::same_as<typename Filter::Filter_t>;
            { f.dst_port(std::declval<unsigned int>()) } -> std::same_as<typename Filter::Filter_t>;
        };

        template <class FilterImpl>
            requires is_filter<FilterImpl>
        class TrafficFilter final : public FilterImpl
        {

        };

    }
    
}
