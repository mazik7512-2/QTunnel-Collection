#pragma once
#include "general.hpp"
#include "structures.hpp"
#include <wintun.h>


namespace QVPN
{
	namespace WinTunExt
	{

		class WinTunDriver
		{

		public:
			using AdapterHandle_t = WINTUN_ADAPTER_HANDLE;
			using Adapter_t = QVPN::Core::DataStructures::Adapter<AdapterHandle_t>;
			using AdapterList_t = QVPN::Core::DataStructures::AdapterList<AdapterHandle_t>;

		private:
			QVPN::Core::DataStructures::AdapterList<WINTUN_ADAPTER_HANDLE> captured_adapters_;
			QVPN::Core::DataStructures::Adapter<WINTUN_ADAPTER_HANDLE> main_adapter_;
			

		private:
			HMODULE wintun_;
			WINTUN_SESSION_HANDLE session_;
			WINTUN_ADAPTER_HANDLE adapter_;

		public:

			WinTunDriver();

			WinTunDriver(const WinTunDriver&) = delete;
			WinTunDriver(WinTunDriver&&) = delete;
			WinTunDriver& operator=(const WinTunDriver&) = delete;
			WinTunDriver& operator=(WinTunDriver&&) = delete;

			virtual ~WinTunDriver();

			void create_adapter();
			void capture_main_adapter();
			void capture_adapter();
			void capture_adapter(std::string_view adapter);
			void capture_adapter(Adapter_t& adapter);
			void close_adapter();
			void close_adapter(Adapter_t& adapter);
			void close_all_adapters();

			std::unique_ptr<AdapterList_t> get_adapters_list() const;

		private:
			void main_adapter_loop_handler();
			void adapter_loop_handler(Adapter_t& adapter);
			void choose_main_adapter(AdapterList_t& adapters);
			void init_wintun();


		};

	}

}