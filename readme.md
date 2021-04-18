### DNS_relay

This is a DNS relay program wrriten by golang. 

You can apply your specific setting to the program by edit config.txt.

### config.txt

If the DNS query is a domain name in the config.txt with a 0.0.0.0 by it, the program will intercept the query.

If the DNS query is a domain name in the config.txt with a non 0.0.0.0 ipv4 address, the dns program will return a response of that ip.

If the DNS query is a domain name not in the config.txt, the program just acts like a proxy, sends it to the true DNS server.