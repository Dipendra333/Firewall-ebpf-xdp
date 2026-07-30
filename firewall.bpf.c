#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u8);
	__uint(max_entries, 10);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} ip_block_map SEC(".maps");

SEC("xdp")
int firewall(struct xdp_md *ctx) {
    
    void *data_end = (void *)(long) ctx->data_end;
    void *data = (void *) (long) ctx->data;
	
    struct ethhdr *eth = data;
    void *next_header = eth + 1;
    if( next_header > data_end)
	    return XDP_ABORTED;

    if(bpf_ntohs(eth->h_proto) != ETH_P_IP)
	    return XDP_PASS;

    struct iphdr *iph = next_header;
    next_header = iph + 1;
    if (next_header > data_end)
	    return XDP_ABORTED;

   __u32 saddr = iph->saddr;
   __u32 src = bpf_ntohl(saddr);

   bpf_printk("IP: %d.%d.%d.%d",
       (src >> 24) & 0xff,
       (src >> 16) & 0xff,
       (src >> 8) & 0xff,
       src & 0xff);
  
   __u8 *drop_ip = bpf_map_lookup_elem(&ip_block_map, &saddr);
   if(drop_ip)
   {
	   bpf_printk("Dropped");
	   return XDP_DROP;
   }

   return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
