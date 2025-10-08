#pragma once

#include "general.hpp"
#include <structures.hpp>

namespace QVPN
{
    namespace Core
    {

        template <typename T>
        concept is_net_driver =
            requires(T t) {
                { true };
                typename T::AdapterList_t;
                typename T::Adapter_t;
                typename T::AdapterHandle_t;
                /*
                { t.create_adapter_impl(std::declval<std::string_view>()) } -> std::same_as<void>;
                { t.close_adapter_impl() } -> std::same_as<void>;
                { t.get_adapter_list_impl() } -> std::same_as<std::unique_ptr<std::vector<std::string>>>;*/
        };

        template <class T>
            requires is_net_driver<T>
        class NetDriver final
        {
        private:
            using AdaptetList_t = T::AdapterList_t;
            T driver_;

        public:

            inline void create_adapter()
            {
                driver_.create_adapter_impl();
            }

            inline std::unique_ptr<AdaptetList_t> get_adapters_list() const
            {
                return driver_.get_adapters_list_impl();
            }

            inline void capture_adapter()
            {
                driver_.capture_adapter_impl();
            }

            inline void capture_adapter(std::string_view adapter)
            {
                driver_.capture_adapter_impl(adapter);
            }

            inline void capture_adapter(T::Adapter_t& adapter)
            {
                driver_.capture_adapter_impl(adapter);
            }

        };
    }
    
}
