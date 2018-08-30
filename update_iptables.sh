sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
sudo /sbin/iptables-save

sudo ip6tables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
sudo /sbin/ip6tables-save
