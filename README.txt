Iptables target transparenly redirecting http request to some (advertaising) page.
Each source source ip redirected only one time.

Ex.:
# iptables -I FORWARD \
                 -i eth0.4000 -o eth0.4001 \
                 -p tcp --dport 80 \
                 -j ADVERT --network 10.199.1.0/24 --url http://google.com --interval 10000

--nerwork: all redirected requests must belong to that network. You may give several networks;
--url: redirect location;
--interval: Interval between redirects in microseconds, prevents web-server overload.

After adding that rule each ip will be one time redirected to http://google.com.
To decide if request may be redirected, xt_ADVERT do check:

1. from last redirect pass more than 'interval' microseconds;
2. source ip was not already redirected;
3. the ip packet is proper http "GET / HTTP/1.1", do not have Referer header and have text/html Accept header;

After that sends to client redirect:
        HTTP/1.1 303 See Other
        Location: http://google.com?host=orig.host.name&path=/
        Connection: close

(orig.host.name taken from Host header)

and tcp RST to both client and server.
