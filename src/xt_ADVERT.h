#ifndef _LINUX_NETFILTER_XT_ADV
#define _LINUX_NETFILTER_XT_ADV

struct ipnet {
        __u32 ip;
        __u32 mask;
        __u32 masklen;
};

#define MAX_NETS 5
#define MIN_MASKLEN 16
#define MAX_URLLEN 80

struct xt_advert_data;

struct xt_advert_tginfo {
        struct ipnet ipnets[MAX_NETS];
        __u32 count;
        __u64 interval; // usec
        char url[MAX_URLLEN+1];

        // private kernel data
	struct xt_advert_data *data __attribute__((aligned(8)));
        __u64 next_time;
        __u8 *flags[MAX_NETS];
};


#endif /* _LINUX_NETFILTER_XT_ADV */
