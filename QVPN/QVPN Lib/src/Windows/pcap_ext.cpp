#pragma once
#include "pcap_ext.hpp"
#include "structures.hpp"
#include <iostream>
#include <stdlib.h>

#pragma comment(lib, "wpcap.lib")

#define WORKING_BUFFER_SIZE 15000
#define PCAP_ERRBUF_SIZE 256


/*
QVPN::Core::DataStructures::Adapter QVPN::PcapExt::PcapNetDriver::convert_from_pcap_adapter(const IP_ADAPTER_ADDRESSES& adapter)
{
	return QVPN::Core::DataStructures::Adapter(adapter.AdapterName, adapter.Description, adapter.FriendlyName, adapter.Flags, adapter.Mtu, std::begin(adapter.PhysicalAddress), std::end(adapter.PhysicalAddress));
}
*/

// RVO 
QVPN::PcapExt::PcapNetDriver::Adapter_t QVPN::PcapExt::PcapNetDriver::convert_from_pcap_adapter(const pcap_if_t* adapter)
{
	return Adapter_t(adapter->name, adapter->description, adapter->name, adapter->flags, 0, std::begin(adapter->addresses->addr->sa_data), std::end(adapter->addresses->addr->sa_data));
}

std::unique_ptr<QVPN::PcapExt::PcapNetDriver::AdapterList_t> QVPN::PcapExt::PcapNetDriver::get_adapters_list_impl() const
{
	/*
	ULONG size_p = WORKING_BUFFER_SIZE;
	IP_ADAPTER_ADDRESSES* ad = new IP_ADAPTER_ADDRESSES[size_p];
	QVPN::Core::DataStructures::AdapterList adapters;
	GetAdaptersAddresses(2, 0, 0, ad, &size_p);
	auto a_cur = ad;
	while (a_cur)
	{
		auto adapter = QVPN::PcapExt::PcapNetDriver::convert_from_pcap_adapter(*a_cur);
		auto [b, e] = adapter.get_phys_addr();
		adapters.emplace_back(adapter.get_name(), adapter.get_desc(), adapter.get_friendly_name(), adapter.get_flags(), adapter.get_mtu(), b, e);
		std::wcout << a_cur->FriendlyName << " " << a_cur->PhysicalAddress << std::endl;
		a_cur = a_cur->Next;
	}
	*/
	pcap_if_t* alldevs;
	char errbuf[PCAP_ERRBUF_SIZE];
	QVPN::PcapExt::PcapNetDriver::AdapterList_t adapters;
	if (pcap_findalldevs(&alldevs, errbuf) != -1)
	{
		for (pcap_if_t* d = alldevs; d != NULL; d = d->next)
		{
			if (d->addresses)
			{
				auto addr = d->addresses->addr->sa_data;
				auto adapter = convert_from_pcap_adapter(d);
				auto [b, e] = adapter.get_phys_addr();
				adapters.emplace_back(adapter.get_name(), adapter.get_desc(), adapter.get_friendly_name(), adapter.get_flags(), adapter.get_mtu(), b, e);
			}

		}
		pcap_freealldevs(alldevs);
	}


	return std::make_unique<decltype(adapters)>(adapters);
}


void packet_handler(u_char* args, const struct pcap_pkthdr* pkthdr, const u_char* packet) 
{

	std::cout << packet << std::endl;

}

void QVPN::PcapExt::PcapNetDriver::capture_adapter_impl(std::string_view adapter)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	//char a[100];
	//wcstombs(a, adapter.data(), 100);
	auto descr = pcap_open_live(adapter.data(), BUFSIZ, 1, -1, errbuf);
	if (descr == NULL)
	{
		printf("pcap_open_live(): %s\n", errbuf);
		return;
	}

	pcap_loop(descr, -1, packet_handler, nullptr);
}


void QVPN::PcapExt::PcapNetDriver::capture_adapter_impl(QVPN::PcapExt::PcapNetDriver::Adapter_t& adapter)
{
	capture_adapter_impl(std::forward<std::string_view>(adapter.get_friendly_name()));
}


// TODO: изменить на более подходящую, а то слишком костыльно
// Проверка на физический адаптер
bool is_physical_adapter(const QVPN::PcapExt::PcapNetDriver::Adapter_t& adapter) {
	std::string name = static_cast<std::string>(adapter.get_desc());
	return (
		name.find("Realtek") != std::string::npos ||
		name.find("Broadcom") != std::string::npos ||
		name.find("Intel") != std::string::npos
		);
}

bool QVPN::PcapExt::AdapterCriteria<QVPN::PcapExt::PcapNetDriver::AdapterHandle_t>::check_criteria(const QVPN::PcapExt::PcapNetDriver::Adapter_t& adapter)
{
	if (adapter.get_flags() & (PCAP_IF_UP | PCAP_IF_RUNNING) && is_physical_adapter(adapter))
		return true;
	return false;
}

