#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>


#define ip_to_sa(ip) ip_to_s(ip, alloca(16))


static
char *
ip_to_s(uint32_t ip, char *s)
{
        uint8_t *p = (uint8_t*)(&ip);
        sprintf(s, "%d.%d.%d.%d", p[3], p[2], p[1], p[0]);
        return s;
}


static
int
parse_ipnet(const char *s, struct ipnet *ipnet)
{
        int m = 32;

        const char *ip = s;
        char *as = NULL;

        char *p = strchr(s, '/');

        if (p != NULL) {
                if ((p - s) < 7 || (p - s) > 15)
                        goto err;

                char *ms = p + 1;

                if (!isdigit(*ms))
                        goto err;

                if (ms[1] &&
                    (!isdigit(ms[1]) || ms[2]))
                        goto err;

                m = atoi(ms);
                if (m < 0 || m > 32)
                        goto err;

                as = alloca(p - s + 1);
                memcpy(as, s, p - s);
                as[p-s] = 0;

                ip = as;
        }

        struct in_addr addr;

        if (0 == inet_aton(ip, &addr))
                goto err;

        ipnet->masklen = m;
        ipnet->mask = m == 0 ? 0 : (~0) << (32 - m);
        ipnet->ip = ntohl(addr.s_addr) & ipnet->mask;

        return 0;

 err:
        return -1;
}


static
int
str_to_ulong(const char *s, char **endptr, unsigned long *n, unsigned long max)
{
        char *ptr;

        if (endptr == NULL)
                endptr = &ptr;

        *n = strtoul(s, endptr, 10);

        if (errno == ERANGE && *n == ULONG_MAX)
                goto err;

        if (*endptr == s)
                goto err;

        if (*n > max)
                goto err;

        return 0;

 err:
        return -1;
}
