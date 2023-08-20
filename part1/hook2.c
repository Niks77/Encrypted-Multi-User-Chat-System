#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/string.h>


#define PTCP_WATCH_PORT     1234  /* HTTP port */

static struct nf_hook_ops nfho;
static struct nf_hook_ops *nf_blockicmppkt_ops = NULL;


const unsigned char *get_ipv4_payload(const struct iphdr *ipHeader)
{
    int ipHeaderLenInBytes = 4 * ipHeader->ihl;
    const unsigned char *transportHeader = (const unsigned char*)(((const char*)(ipHeader)) + ipHeaderLenInBytes);
    return transportHeader;
}

const struct tcphdr *get_tcp_header_from_ipv4_header(const struct iphdr *ipHeader)
{
    const struct tcphdr *tcpHeader = (const struct tcphdr *)get_ipv4_payload(ipHeader);
    return tcpHeader;
}

const unsigned char *get_tcp_payload(const struct tcphdr *tcp_header)
{
    const unsigned char *tcp_payload_start = (const unsigned char*)tcp_header + (4 * tcp_header->doff);
    return tcp_payload_start;
}

int get_tcp_payload_size(const struct iphdr *ip_header)
{
    const struct tcphdr *tcph = get_tcp_header_from_ipv4_header(ip_header);
    const unsigned char *tcp_payload_start = get_tcp_payload(tcph);
    int payload_length = ntohs(ip_header->tot_len) - (tcp_payload_start - (const unsigned char*)ip_header);
    return payload_length;
}

static unsigned int ptcp_hook_func(const struct nf_hook_ops *ops,
                                   struct sk_buff *skb,
                                   const struct net_device *in,
                                   const struct net_device *out,
                                   int (*okfn)(struct sk_buff *))
{
    struct iphdr *iph;          /* IPv4 header */
    struct tcphdr *tcph;        /* TCP header */
    u16 sport, dport;           /* Source and destination ports */
    u32 saddr, daddr;           /* Source and destination addresses */
    unsigned char *user_data;   /* TCP data begin pointer */
    unsigned char *tail;        /* TCP data end pointer */
    unsigned char *it;          /* TCP data iterator */

    /* Network packet is empty, seems like some problem occurred. Skip it */
    if (!skb)
        return NF_ACCEPT;

    iph = ip_hdr(skb);          /* get IP header */

    /* Skip if it's not TCP packet */
    if (iph->protocol != IPPROTO_TCP)
        return NF_ACCEPT;

    tcph = tcp_hdr(skb);        /* get TCP header */

    /* Convert network endianness to host endiannes */
    saddr = ntohl(iph->saddr);
    daddr = ntohl(iph->daddr);
    sport = ntohs(tcph->source);
    dport = ntohs(tcph->dest);

    /* Watch only port of interest */
    if (dport != PTCP_WATCH_PORT)
        return NF_ACCEPT;

    /* Calculate pointers for begin and end of TCP packet data */
    // struct tcphdr *tcph = NULL;
    // struct iphdr *iph = NULL;
    // int tcp_payload_size = 0;
    // char *tcp_payload = NULL;

    // if(NULL == skb) return false;
 
    // // iph = ip_hdr(skb);
    // if(NULL == iph) return false;

    // // tcph = tcp_hdr(skb);
    // if(NULL == tcph) return false;

    // tcp_payload = get_tcp_payload(tcph);
    // tcp_payload_size = get_tcp_payload_size(iph);

    struct skb_shared_info *shinfo = skb_shinfo(skb);
    // struct sk_buff *frag = shinfo->frag_list;
    // unsigned int len = shinfo -> nr_frags;
    // if(len > 0){
    //     struct iphdr *iph1 = ip_hdr(frag); 
    //     struct tcphdr *tcph1 = tcp_hdr(frag);
    //     unsigned char* tcp_payload1 = get_tcp_payload(tcph1);
    //     int tcp_payload_size1 = get_tcp_payload_size(iph1);
    //     int i;

    //     for(i =0; i < tcp_payload_size1; i++) {
    //         printk(KERN_INFO "%02x ", tcp_payload1[i]);
    //     }

    // }

    if (shinfo->nr_frags > 0) {
        int i;

        printk(KERN_INFO "Fragmented packet with %d fragments\n", shinfo->nr_frags);

        // Iterate over fragments
        for (i = 0; i < shinfo->nr_frags; i++) {
            // struct skb_frag_t *frag = &shinfo->frags[i];
            skb_frag_t *frag = &shinfo->frags[i];
            unsigned int offset = skb_frag_off(frag);
            struct page *page = skb_frag_page(frag);
            unsigned char *data;

            size_t size = frag->bv_len;
    // Get a pointer to the data in the page
            data = page_address(page) + offset;

            // Modify the data
            // For example, to flip the 8th bit of the first byte of the data:
            if(size > 50)
                data[50] ^= 0x01;


            // void *buf = kmalloc(size, GFP_KERNEL);
            // char *buf = kmalloc(size, GFP_KERNEL);
            // memcpy(buf, fragment, size);
            // kunmap(skb_frag_page(frag));

            // Log fragment information
            printk(KERN_INFO "Fragment %d: Offset=%u, Size=%u\n",
                    i, frag->bv_offset, frag->bv_len);


            int j;
            for(j =0; j < size; j++) {
                printk(KERN_INFO "%02x ", data[j]);
            }
            printk(KERN_INFO "\n\n");
            // kfree(data);
        }
    } else {
        printk(KERN_INFO "Not a fragmented packet\n");
    }


    /* ----- Print all needed information from received TCP packet ------ */

    /* Show only HTTP packets */
    // if (user_data[0] != 'H' || user_data[1] != 'T' || user_data[2] != 'T' ||
    //         user_data[3] != 'P') {
    //     return NF_ACCEPT;
    // }

    /* Print packet route */
    printk(KERN_INFO "print_tcp: %pI4h:%d -> %pI4h:%d\n", &saddr, sport,
                              &daddr, dport);

    /* Print TCP packet data (payload) */
    printk(KERN_INFO "print_tcp: data:\n");
    // int i;

    // for(i =0; i < tcp_payload_size; i++) {
    //     printk(KERN_INFO "%02x ", tcp_payload[i]);
    // }

    // for (it = user_data; it != tail; ++it) {
    //     char c = *(char *)it;

    //     if (c == '\0')
    //         break;

    //      printk(KERN_INFO "%c", c);
    // }
    //  printk(KERN_INFO "\n\n");

    return NF_ACCEPT;
}

static int __init ptcp_init(void)

{
    nf_blockicmppkt_ops = (struct nf_hook_ops*)kcalloc(1,  sizeof(struct nf_hook_ops), GFP_KERNEL); 
    int res;

    nf_blockicmppkt_ops->hook = (nf_hookfn *)ptcp_hook_func;    /* hook function */
    nf_blockicmppkt_ops->hooknum = NF_INET_LOCAL_IN;         /* received packets */
    nf_blockicmppkt_ops->pf = PF_INET;                          /* IPv4 */
    nf_blockicmppkt_ops->priority = NF_IP_PRI_CONNTRACK_DEFRAG;            /* max hook priority */

    // res = nf_register_hook(&nfho);
    nf_register_net_hook(&init_net, nf_blockicmppkt_ops);
    // if (res < 0) {
    //     pr_err("print_tcp: error in nf_register_hook()\n");
    //     return res;
    // }

    pr_debug("print_tcp: loaded\n");
    return 0;
}

static void __exit ptcp_exit(void)
{
    nf_unregister_net_hook(&init_net, nf_blockicmppkt_ops);
    pr_debug("print_tcp: unloaded\n");
}

module_init(ptcp_init);
module_exit(ptcp_exit);

MODULE_AUTHOR("Sam Protsenko");
MODULE_DESCRIPTION("Module for printing TCP packet data");
MODULE_LICENSE("GPL");
