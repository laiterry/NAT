IP="10.3.1.17"	# public interface
LAN="10.4.17.1/27"
MASK="27"

echo "1" >  /proc/sys/net/ipv4/ip_forward
iptables -t nat -F
iptables -t filter -F
iptables -t mangle -F
iptables -t filter -A FORWARD -j QUEUE -p tcp -s ${LAN} ! -d ${IP} --dport 10000:12000
iptables -t mangle -A PREROUTING -j QUEUE -p tcp -d ${IP} --dport 10000:12000
iptables -t filter -A FORWARD -j QUEUE -p udp -s ${LAN} ! -d ${IP} --dport 10000:12000
iptables -t mangle -A PREROUTING -j QUEUE -p udp -d ${IP} --dport 10000:12000
iptables -t filter -A FORWARD -j QUEUE -p icmp -s ${LAN} ! -d ${IP} 
iptables -t mangle -A PREROUTING -j QUEUE -p icmp -d ${IP} 
./nat $IP 10.4.17.1 $MASK
