#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <xtables.h>
#include <sys/types.h>
#include <getopt.h>
#include <stdlib.h>
#include "xt_ADVERT.h"

#include "utils.c"


#define INTERVAL 1000 // 1000us = 1ms
#define INTERVAL_MAX 2000000000


enum {
        NETS_PRESENT     = 1 << 0,
        URL_PRESENT      = 1 << 1,
        INTERVAL_PRESENT = 1 << 2,
};


static void advert_help(void)
{
	printf("advert match options:\n");
}


static void advert_init(struct xt_entry_target *target)
{
	struct xt_advert_tginfo *info = (void *)target->data;
        info->interval = INTERVAL;
}


static void advert_print(const void *entry, const struct xt_entry_target *target,
                         int numeric)
{
        const struct xt_advert_tginfo *info = (const void *)target->data;
        const struct ipnet *net = info->ipnets;
        for (int i = 0; i < info->count; i++, net++)
                printf(" network:%s/%d", ip_to_sa(net->ip), net->masklen);
        printf(" url:%s", info->url);
        printf(" interval:%llu", info->interval);
}


static
void
advert_save(const void *entry, const struct xt_entry_target *target)
{
        const struct xt_advert_tginfo *info = (const void *)target->data;

        const struct ipnet *net = info->ipnets;

        for (int i = 0; i < info->count; i++, net++)
                printf(" --network %s/%d", ip_to_sa(net->ip), net->masklen);

        printf(" --url %s", info->url);

        if (info->interval != INTERVAL)
                printf(" --interval %llu", info->interval);
}


static
int
advert_parse(int c, char **argv, int invert, unsigned int *flags,
             const void *entry, struct xt_entry_target **target)
{
        struct xt_advert_tginfo *info = (void*)(*target)->data;

        if (info->count == MAX_NETS)
                xtables_error(PARAMETER_PROBLEM, "ADVERT: too many nets");

        struct ipnet *net = info->ipnets + info->count;

        switch (c) {
        case 'n':
                if (-1 == parse_ipnet(optarg, net))
                        xtables_error(PARAMETER_PROBLEM, "ADVERT: bad network given");

                if (net->masklen < MIN_MASKLEN)
                        xtables_error(PARAMETER_PROBLEM, "ADVERT: too big network");

                // printf("%s parsed %s/%d\n", optarg, ip_to_sa(net->ip), net->masklen);

                info->count++;

                *flags |= NETS_PRESENT;

                return true;

        case 'u':
                if (*flags & URL_PRESENT)
                        xtables_error(PARAMETER_PROBLEM, "ADVERT: url already set");

                __u32 len = strlen(optarg);

                if (len > MAX_URLLEN)
                        xtables_error(PARAMETER_PROBLEM, "ADVERT: url too long");

                // info->url_len = len;

                memcpy(info->url, optarg, len+1);

                *flags |= URL_PRESENT;

                return true;
        case 'i':
                if (*flags & INTERVAL_PRESENT)
                        xtables_error(PARAMETER_PROBLEM, "ADVERT: interval already set");

                {
                        char *endptr;
                        unsigned long n;

                        if (-1 == str_to_ulong(optarg, &endptr, &n, INTERVAL_MAX) || *endptr)
                                xtables_error(PARAMETER_PROBLEM, "ADVERT: incorrect interval");

                        info->interval = n;
                }

                *flags |= INTERVAL_PRESENT;

                return true;

        default:
                return false;
        }

        return false;
}



static const struct option advert_opts[] = {
        { .name = "network", .has_arg = true, .val = 'n'},
        { .name = "url", .has_arg = true, .val = 'u'},
        { .name = "interval", .has_arg = true, .val = 'i'},
        {NULL},
};


static
void
final_check(unsigned int flags)
{
        if (!(flags & NETS_PRESENT))
                xtables_error(PARAMETER_PROBLEM, "ADVERT: no nets given");
        if (!(flags & URL_PRESENT))
                xtables_error(PARAMETER_PROBLEM, "ADVERT: no url given");
}


static struct xtables_target advert_tg_reg = {
	.family		= NFPROTO_IPV4,
	.name		= "ADVERT",
	.version	= XTABLES_VERSION,
	.size		= XT_ALIGN(sizeof(struct xt_advert_tginfo)),
	.userspacesize	= offsetof(struct xt_advert_tginfo, data),
	.help		= advert_help,
	.init		= advert_init,
	.print		= advert_print,
	.save		= advert_save,
	.parse	= advert_parse,
	.extra_opts	= advert_opts,
        .final_check    = final_check,
};


static void _init(void)
{
        xtables_register_target(&advert_tg_reg);
}
