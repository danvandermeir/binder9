This is a simplified way to configure a DNS server to do the things you want. Since this script is able to do so much regarding DNS, it's easier to list things it does not do:

1. Have a GUI
2. Domain blocking
3. Serve authoratative only answers on LAN ints that can utilize a function similar to LANHOSTS 'all,' function

To figure out what it CAN do, read the begining of the script.

Personally, I developed this script as `bind9`/`named` can be extremely complex involving a multiple file heirarchy which this script handles far more easily. This is specifically to work in conjunction with PiHole as PiHole does not deal with recursive resolution or split horizon DNS. The trick being to configure your DHCP server to distribute your `bind9` server as the first DNS server on each network (with the second being your PiHole), configure this script's DNSWANINTS to answer only authorative names across your various networks, add a DNSLANINTS on one specific interface for "remote network" with the IP of the PiHole (E.G. '10.0.0.2/32,eth4' in DNSLANINTS), and configure PiHole to forward to `bind9`. Not to say there aren't a lot of thoughts on how these files should be laid out (I am open to suggestions).

It contains BASH array variables with descriptions. This snippet contains some examples.
```
#	WANs or interfaces to serve only authoratative responses (E.G. 'eth1' will only work with 'public,' or LANHOSTS specifically naming DNSWANINTS below) - supersedes duplicates in DNSLANINTS
DNSWANINTS=('eth2' 'wg0')

#	interface names to serve general DNS requests on (E.G. 'eth0') - superseded by duplicates in DNSWANINTS
#	prepend CIDR network for non-local (VLANs?) or limited networks routing DNS requests here (E.G. '192.168.0.0/16,eth0'), assure non-local requests arrive on the default gateway interface
#	BE ABSOLUTELY TO NOT CREATE AN OPEN RESOLVER!! DO NOT RESOLVE REQUESTS TO "THE INTERNET"!!!
DNSLANINTS=('eth0' 'eth1' 'eth3' '10.16.0.0/24,eth0' '10.15.0.0/24,eth0')

#	to force requests to be forwarded to another domain name server for a specific interface list the DNS IP here
#	this array should match DNSLANINTS, blank entries treated as default resolver type unless RESOLVERS set, overides RESOLVERS
FORWARDERS=('10.18.0.2' '' '' '1.1.1.1' '')

#	to force recursive requests out specific interfaces when received on a specific interface enter the interface name or IP here
#	this array should match DNSLANINTS, blank entries treated as default resolver type, FORWARDERS will overide this option
RESOLVERS=('' '10.17.0.2' '' '' '' 'eth2')

#	hostnames to resolve as authorative server (this includes subdomains, such subdomains could be overiden with a new hostname entry)
HOSTNAMES=('1.tld' '2.tld' '3.4.tld' '4.tld' '5.tld')

#	the IP the HOSTNAMES entry will be resolved to for requests on all interfaces listed in DNSLANINTS
#	prepending 'all,' to an entry will take a host portion of an IP (E.G. 'all,.5') and attempt to apply that host to all DNSLANINTS listed interface networks
#	prepending an interface name listed in DNSLANINTS will make only that interface redirect hostname requests to the specified IP (E.G. 'eth0,192.168.8.5')
#	prepending 'public,' to the specified IP causes "WAN" connections to respond to requests only for listed hostnames (E.G. 'public,64.63.62.61')
LANHOSTS=('10.0.0.1' 'all,.3' 'eth2,69.68.67.66' 'public,69.68.67.65' 'eth0,10.0.0.3')
```
