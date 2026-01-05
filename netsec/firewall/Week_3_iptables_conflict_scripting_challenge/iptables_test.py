import ipaddress

network = ipaddress.IPv4Network("10.0.0.0/20")

network2 = ipaddress.IPv4Network("10.0.1.0/24")

print(network2.overlaps(network))

