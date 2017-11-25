from firewall import Firewall

print("PROVIDED")
# Check provided tests
fw_provided = Firewall('provided_example.csv')
assert(fw_provided.accept_packet("inbound", "tcp", 80, "192.168.1.2")) # matches first rule
assert(fw_provided.accept_packet("inbound", "udp", 53, "192.168.2.1")) # matches third rule
assert(fw_provided.accept_packet("outbound", "tcp", 10234, "192.168.10.11")) # matches second rule true
assert(fw_provided.accept_packet("inbound", "tcp", 81, "192.168.1.2")==False)
#false
assert(fw_provided.accept_packet("inbound", "udp", 24, "52.12.48.92")==False)
#false

print("\nFULL RANGE")
# Check if a full range (always returns true)
fw_full_range = Firewall('full_range.csv')
assert(fw_full_range.accept_packet("inbound", "tcp", 1, "0.0.0.0"))
assert(fw_full_range.accept_packet("inbound", "tcp", 22, "125.255.35.8"))
assert(fw_full_range.accept_packet("inbound", "tcp", 65535, "255.255.255.255"))

# Checks that values in one dir/protocol do NOT affect another
# Also checks that functions work on empty lists
assert(fw_full_range.accept_packet("inbound", "udp", 1, "0.0.0.0")==False)
assert(fw_full_range.accept_packet("outbound", "tcp", 22, "125.255.35.8")==False)
assert(fw_full_range.accept_packet("outbound", "udp", 65535, "255.255.255.255")==False)


print("\nOVERLAPS")

fw_many_overlaps = Firewall('overlaps.csv')

# All ranges
overlaps = [
	(20, 24, ['0.0.0.0', '2.2.2.2']),
	(25, 29, ['0.0.0.0', '2.2.2.2', '3.3.3.3']),
	(30, 30, ['0.0.0.0', '2.2.2.2', '3.3.3.3', '6.6.6.6']),
	(31, 32, ['0.0.0.0', '6.6.6.6']),
	(33, 34, ['0.0.0.0']),
	(35, 37, ['0.0.0.0', '1.1.1.1']),
	(38, 38, ['0.0.0.0', '1.1.1.1', '4.4.4.4']),
	(39, 40, ['0.0.0.0', '1.1.1.1']),
	(41, 44, ['1.1.1.1']),
	(45, 45, ['1.1.1.1', '5.5.5.5']),
	(46, 50, [])
]
possible_ips = ['0.0.0.0', '1.1.1.1', '2.2.2.2', '3.3.3.3', '4.4.4.4', '5.5.5.5', '6.6.6.6']

# Test each possible value for each range
for start, end, good_ips in overlaps:
	for port in range(start, end+1):
		for ip in possible_ips:
			is_in_section = fw_many_overlaps.accept_packet("inbound", "tcp", port, ip)

			if ip in good_ips:
				assert is_in_section, "port: {}; ip: {}".format(port, ip)
			else:
				assert not is_in_section, "port: {}; ip: {}".format(port, ip)



