#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter/x_tables.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <net/tcp.h>
#ifdef CONFIG_BRIDGE_NETFILTER
#	include <linux/netfilter_bridge.h>
#endif
#include "xt_ADVERT.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Antipov Alexey <a.antipov@sumtel.ru>");
MODULE_DESCRIPTION("xtables module redirecting to advertasing page");


#define HTTP_REDIRECT_FORMAT                            \
        "HTTP/1.1 303 See Other\r\n"                    \
        "Location: %s?host=%s&path=%s\r\n"              \
        "Connection: close\r\n\r\n"


#define MAX_HDR 15

#define HTTP_HDR_BUFSIZE 1450
#define REDIRECT_BUF_SIZE 256

#define TH_FIN   0x01
#define TH_RST   0x04
#define TH_PUSH  0x08
#define TH_ACK   0x10


#define PDEBUG(fmt, args...) printk(KERN_DEBUG KBUILD_MODNAME ": " fmt "\n", ## args)


struct xt_advert_data {
        spinlock_t time_lock;
};


// based on xt_REJECT.c
static
int
tcp_send(struct sk_buff *oldskb,
         const char *text, size_t text_len,
         u32 saddr, u32 daddr,
         u16 sport, u16 dport,
         u32 seq, u32 ack, u8 flags)
{
	struct sk_buff *nskb;
	struct iphdr *niph;

	nskb = alloc_skb(sizeof(struct iphdr) + sizeof(struct tcphdr) + text_len + LL_MAX_HEADER, GFP_ATOMIC);
	if (!nskb)
		return -1;

	skb_reserve(nskb, LL_MAX_HEADER);

	skb_reset_network_header(nskb);
	niph = (struct iphdr *)skb_put(nskb, sizeof(struct iphdr));
        // memset
	niph->version = 4;
	niph->ihl = sizeof(struct iphdr) / 4;
	niph->tos = 0;
	niph->id = 0;
	niph->frag_off = htons(IP_DF);
	niph->protocol = IPPROTO_TCP;
	niph->check = 0;
	niph->saddr = saddr;
	niph->daddr = daddr;

	skb_reset_transport_header(nskb);
	struct tcphdr *tcph = (struct tcphdr *)skb_put(nskb, sizeof(struct tcphdr));
	memset(tcph, 0, sizeof(*tcph));
	tcph->source = sport;
	tcph->dest = dport;
	tcph->doff = sizeof(struct tcphdr) / 4;

        tcph->seq = htonl(seq); 
        tcph->ack_seq = htonl(ack);

        ((u8*)tcph)[13] = flags;

        if (text_len)
                memcpy(skb_put(nskb, text_len), text, text_len);

	tcph->check = ~tcp_v4_check(sizeof(struct tcphdr) + text_len, niph->saddr,
				    niph->daddr, 0);
	nskb->ip_summed = CHECKSUM_PARTIAL;
	nskb->csum_start = (unsigned char *)tcph - nskb->head;
	nskb->csum_offset = offsetof(struct tcphdr, check);

	/* ip_route_me_harder expects skb->dst to be set */
	skb_dst_set_noref(nskb, skb_dst(oldskb));

	nskb->protocol = htons(ETH_P_IP);
	if (ip_route_me_harder(nskb, RTN_UNSPEC))
		goto free_nskb;

	niph->ttl = ip4_dst_hoplimit(skb_dst(nskb));

	/* "Never happens" */
	if (nskb->len > dst_mtu(skb_dst(nskb)))
		goto free_nskb;

	nf_ct_attach(nskb, oldskb);

        ip_local_out(nskb);

	return 0;

 free_nskb:
	kfree_skb(nskb);
        return -1;
}


static
unsigned int
advert_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
        struct xt_advert_tginfo *info = (void*)par->matchinfo;
        
        u64 now = jiffies_to_usecs(get_jiffies_64()); // 1/1000000s

        if (info->next_time && info->next_time > now)
                goto pass;

        const struct iphdr *iph = ip_hdr(skb);

	if (iph->frag_off & htons(IP_OFFSET))
		goto pass;
        
        if (IPPROTO_TCP != iph->protocol)
                goto pass;

	if (skb_rtable(skb)->rt_flags & (RTCF_BROADCAST | RTCF_MULTICAST))
                goto pass;

	if (nf_ip_checksum(skb, par->hooknum, ip_hdrlen(skb), IPPROTO_TCP))
                goto pass;

        // const struct tcphdr *tcph = skb_tcp_header(skb, iph);
        struct tcphdr _tcp;
        const struct tcphdr *tcph = skb_header_pointer(skb, iph->ihl*4, sizeof(_tcp), &_tcp);
        if (tcph == NULL)
                // error
                goto pass;

	if (tcph->rst)
                goto pass;

        u8 *pflag = NULL;

        // find if this ip already redirected
        {
                u32 srcaddr = ntohl(iph->saddr);
                struct ipnet *net = info->ipnets;
                for (int i = 0; i < info->count; i++, net++) {
                        if (net->ip == (srcaddr & net->mask)) {
                                u32 nip = ~net->mask & srcaddr;
                                pflag = info->flags[i] + nip;
                                break;
                        }
                }
        }

        if (pflag == NULL)
                goto pass;
        
        if (*pflag > 0)
                goto pass;
        
        u32 data_offset = iph->ihl * 4 + tcph->doff * 4;
        u32 data_size = skb->len - data_offset;
        
        char *http_path = NULL;
        char *http_host = NULL;
        char *accept = NULL;
        char buf[HTTP_HDR_BUFSIZE];

        // try parse http request header
        {
                u32 size = min(data_size, (u32)sizeof(buf));

                if (size < 16)
                        goto pass;
                
                if (skb_copy_bits(skb, data_offset, buf, size) < 0)
                        // error
                        goto pass;
        
                int h = 0;
                char *e = NULL;

                for (char *p = buf; p < buf + size; h++, p = e + 1) {
                        
                        if (h == MAX_HDR)
                                goto pass;
                        
                        size_t buflen = size - (p - buf);

                        e = memchr(p, '\n', buflen);
                        
                        if (!e)
                                goto pass;
                        
                        if (e[-1] != '\r')
                                goto pass;

                        size_t hlen = e - p - 1;
                        
                        if (hlen == 0)
                                break;
                        
                        e[-1] = 0;
                        
                        if (h == 0) {
                                if (0 != memcmp(p, "GET / HTTP/1.1", 14))
                                        goto pass;
                                
                                http_path = "/";
#if 0
                                char *tmp = p + 4;
                                char *sp = memchr(tmp, ' ', buflen - 4);
                                if (sp) {
                                        *sp = 0;
                                        http_path = tmp;
                                }
#endif
                                continue;
                        }
                        
                        if (hlen >= (6 + 5) && 0 == memcmp(p, "Host: ", 6)) {
                                http_host = p + 6;
                                continue;
                        }
                        
                        if (hlen > (8 + 10) && 0 == memcmp(p, "Accept: ", 8)) {
                                if (0 == memcmp(p + 8, "text/html,", 10)) {
                                        accept = p + 8;
                                        continue;
                                }
                                else
                                        goto pass;
                        }

                        if (hlen > 9 && 0 == memcmp(p, "Referer: ", 9))
                                goto pass;
                }
        }
        
        if (http_host == NULL || http_path == NULL || accept == NULL)
                goto pass;

        // advance next_time, remember ip as redirected
        {
                spin_lock_bh(&info->data->time_lock);

                if ((info->next_time && info->next_time > now) || *pflag > 0) {
                        spin_unlock_bh(&info->data->time_lock);
                        goto pass;
                }
                
                info->next_time = now + info->interval;
                *pflag = 1;
                
                spin_unlock_bh(&info->data->time_lock);
        }

        // do redirect
        {
                u32 seq = ntohl(tcph->seq);
                u32 ack_seq = ntohl(tcph->ack_seq);

                char redirect_buf[REDIRECT_BUF_SIZE];
                int len = snprintf(redirect_buf, REDIRECT_BUF_SIZE,
                                   HTTP_REDIRECT_FORMAT, info->url, http_host, http_path);
                if (len >= REDIRECT_BUF_SIZE)
                        goto pass;

                PDEBUG("redirect %pI4n to %s from %s%s", &iph->saddr, info->url, http_host, http_path);

                tcp_send(skb, redirect_buf, len,
                         iph->daddr, iph->saddr,
                         tcph->dest, tcph->source,
                         ack_seq, seq + data_size,
                         TH_ACK|TH_FIN|TH_PUSH);

                tcp_send(skb, NULL, 0,
                         iph->daddr, iph->daddr,
                         tcph->dest, tcph->source,
                         ack_seq + len + 1, 0,
                         TH_FIN|TH_RST);
                
                tcp_send(skb, NULL, 0,
                         iph->saddr, iph->daddr,
                         tcph->source, tcph->dest,
                         seq, ack_seq + data_size,
                         TH_RST);

        }
        
        return NF_DROP;

 pass:
        return XT_CONTINUE;
}


static
int
advert_tg_checkentry(const struct xt_tgchk_param *par)
{
        struct xt_advert_tginfo *info = par->targinfo;

        PDEBUG("url: %s", info->url);

        /* PDEBUG("interval=%llu", info->interval); */
        /* PDEBUG("nets count=%u", info->count); */

        struct ipnet *net = info->ipnets;
        for (int i = 0; i < info->count; i++, net++) {
                u32 size = ~net->mask + 1;
                /* PDEBUG("%d. %pI4h/%d, size=%d", i+1, &net->ip, net->masklen, size); */
                char *p = kmalloc(size, GFP_KERNEL);
                memset(p, 0, size);
                info->flags[i] = p;
        }

        info->data = kmalloc(sizeof(struct xt_advert_data), GFP_KERNEL);
        spin_lock_init(&info->data->time_lock);

        return 0;
}


static
void
advert_tg_destroy(const struct xt_tgdtor_param *par)
{
        struct xt_advert_tginfo *info = par->targinfo;
        for (int i = 0; i < info->count; i++)
                kfree(info->flags[i]);

        kfree(info->data);
}


static struct xt_target advert_tg_reg __read_mostly = {
        .name       = "ADVERT",
        .revision   = 0,    
        .family     = NFPROTO_IPV4,
        .proto      = IPPROTO_TCP,
	.table      = "filter",
	.hooks      = (1 << NF_INET_FORWARD),
	.target     = advert_tg,
        .checkentry = advert_tg_checkentry,
        .destroy    = advert_tg_destroy,
        .targetsize = sizeof(struct xt_advert_tginfo),
        .me         = THIS_MODULE,
};


static int __init advert_tg_init(void)
{       
        return xt_register_target(&advert_tg_reg);
}


static void __exit advert_tg_exit(void)
{
	xt_unregister_target(&advert_tg_reg);
}


module_init(advert_tg_init);
module_exit(advert_tg_exit);
