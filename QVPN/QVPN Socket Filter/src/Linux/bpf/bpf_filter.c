typedef unsigned short __sum16;
typedef unsigned int __wsum;


#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>




struct filter_key {

	// TODO: добавить сюда поля для ipv6

	__u8 net_proto;
	__u8 transport_proto;

	__u32 src_ip;
	__u16 src_port;

	__u32 dst_ip;
	__u16 dst_port;

} __attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, struct filter_key);
	__type(value, __u8);

} filter_map SEC(".maps");


int filter_by_addr_port_ipv4(struct __sk_buff* skb)
{
	void* data = (void*)(long)skb->data;
	void* data_end = (void*)(long)skb->data_end;

	struct iphdr* ip = data;

	__u8 net = ip->version;
	__u8 transport = ip->protocol;

	__u32 src = ip->saddr;
	__u32 dst = ip->daddr;
	__u16 src_port;
	__u16 dst_port;

	struct tcphdr* tcp = (struct tcphdr*)(ip + 1);
	struct udphdr* udp = (struct udphdr*)(ip + 1);
	char* custom = (char*)(ip + 1);

	switch (transport)
	{
	case IPPROTO_TCP:
		src_port = tcp->source;
		dst_port = tcp->dest;
		break;
	case IPPROTO_UDP:
		src_port = udp->source;
		dst_port = udp->dest;
		break;
	default:
		src_port = *custom << 8 | *(custom + 1);
		dst_port = *(custom + 2) << 8 | *(custom + 3);
		break;
	}

	struct filter_key key = {
		.net_proto = net,
		.transport_proto = transport,

		.src_ip = src,
		.src_port = src_port,

		.dst_ip = dst,
		.dst_port = dst_port,
	};

	__u8* valid = bpf_map_lookup_elem(&filter_map, &key);

	if (valid && *valid)
		return -1; // accept
	return 0; // reject
}

int filter_by_addr_port_ipv6(struct __sk_buff* skb)
{
	return 0; // reject
}

SEC("socket")
int filter_by_addr_port(struct __sk_buff* skb)
{
	void* data = (void*)(long)skb->data;
	void* data_end = (void*)(long)skb->data_end;

	struct iphdr* ip = data;

	if ((void*)(ip + 1) > data_end)
		return 0;
	
	switch (ip->version)
	{
	case 4:
		return filter_by_addr_port_ipv4(skb);
		break;
	case 6:
		return filter_by_addr_port_ipv6(skb);; // reject
		break;
	default:
		return 0; // reject
		break;
	}

}

char _license[] SEC("license") = "GPL";