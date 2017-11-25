from ipaddress import IPv4Address
from queue import PriorityQueue
import csv
import bisect

class Firewall(object):

    # CORE FUNCTION
    def __init__(self, csv_path):
        # A dictionary containing a list for each dir/protocol combination
        self.rules = {"inbound" : {"tcp": [], "udp": []},\
                      "outbound" : {"tcp": [], "udp": []}}

        # Import csv and add rules one by one to the correct list (maintaining order)
        with open(csv_path) as f:
            reader = csv.reader(f)
            for direction, protocol, port, ip_address in reader:
                port_range = [int(p) for p in port.strip().split('-')]
                ip_range = [IPv4Address(p) for p in ip_address.strip().split('-')]
                
                if len(port_range) == 2:
                    pr = PortRange(port_range[0], port_range[1], [ip_range])
                else:
                    pr = PortRange(port_range[0], addrs = [ip_range])

                self.add_rule(direction, protocol, pr)


        # For each range of ports, condense all the addrs
        for direction in self.rules:
            for protocol in self.rules[direction]:
                for p_range in self.rules[direction][protocol]:
                    p_range.condense_addrs()


    # CORE FUNCTION
    def accept_packet(self, direction, protocol, port, ip_address):
        ports_ranges = self.rules[direction][protocol]

        port = PortRange(int(port))
        ip_address = IPv4Address(ip_address)

        i = bisect.bisect_right(ports_ranges, port)
        if i:
            closest_pr = ports_ranges[i-1]
            if closest_pr.contains_port_in_range(port):
                return closest_pr.contains_address_in_range(ip_address)

        return False

    # Add a single port rule
    def add_rule(self, direction, protocol, port):
        ports_ranges = self.rules[direction][protocol]

        if not ports_ranges:
            ports_ranges.append(port)
            return

        cur_range = port
        new_rules = []
        for pr in ports_ranges:
            if cur_range.left <= pr.left:
                left, cur_range = self.merge_rules(cur_range, pr)
            else:
                left, cur_range = self.merge_rules(pr, cur_range)
            new_rules.extend(left)
        if cur_range:
            new_rules.append(cur_range)

        self.rules[direction][protocol] = new_rules


    '''
    Merges two rule ranges together to create a new set of rule ranges
    for each segment.  The left bound of rule0 is assumed to be less than 
    or equal to the left bound of rule1.  Returns a list of
    passed ranges and a single, final continuing range
    '''
    def merge_rules(self, rule0, rule1):
        if rule0.is_single() and rule1.is_single():
            if rule0.left == rule1.left:
                return [], PortRange(rule0.left, addrs=rule0.addrs + rule1.addrs)
            else:
                return [rule0], rule1

        elif not rule0.is_single() and not rule1.is_single():
        # Definitely True: l0 < l1, l0 < r0, l1 < r1 

            if rule0.left == rule1.left:
                # l0 == l1 < r0 == r1 --> full overlap
                if rule0.right == rule1.right:
                    return [], PortRange(rule0.left, rule0.right, rule0.addrs+rule1.addrs)

                # l0 == l1 < r0 < r1 --> | == } - )
                elif rule0.right < rule1.right:
                    out = [PortRange(rule0.left, rule0.right, rule0.addrs+rule1.addrs)]
                    return out, PortRange(rule0.right+1, rule1.right, list(rule1.addrs))

                # l0 == l1 < r1 < r0 --> | == ) - }
                else:
                    out = [PortRange(rule0.left, rule1.right, rule0.addrs+rule1.addrs)]
                    return out, PortRange(rule1.right+1, rule0.right, list(rule0.addrs)) 

            elif rule1.left < rule0.right:
                # l0 < l1 < r0==r1 --> { - ( == |
                if rule0.right == rule1.right:
                    out = [PortRange(rule0.left, rule1.left-1, list(rule0.addrs))]
                    return out, PortRange(rule1.left, rule1.right, rule0.addrs+rule1.addrs)

                # l0 < l1 < r0 < r1 --> { -- ( == } -- )  
                elif rule0.right < rule1.right:
                    out = []
                    out.append(PortRange(rule0.left, rule1.left-1, list(rule0.addrs)))
                    out.append(PortRange(rule1.left, rule0.right, rule0.addrs+rule1.addrs))
                    return out, PortRange(rule0.right+1, rule1.right, list(rule1.addrs))
                
                # l0 < l1 < r1 < r0 --> { -- ( == ) -- }
                else:
                    out = []
                    out.append(PortRange(rule0.left, rule1.left-1, list(rule0.addrs)))
                    out.append(PortRange(rule1.left, rule1.right, rule0.addrs+rule1.addrs))
                    return out, PortRange(rule1.right+1, rule0.right, list(rule0.addrs))
            
            elif rule0.right < rule1.right:
                # l0 < r0==l1 < r1 --> { -- | -- )
                if rule0.right == rule1.left:
                    out = []
                    out.append(PortRange(rule0.left, rule0.right-1, list(rule0.addrs)))
                    out.append(PortRange(rule0.right, addrs=rule0.addrs+rule1.addrs))
                    return out, PortRange(rule1.left+1, rule1.right, list(rule1.addrs))

                # l0 < r0 < l1 < r1 --> no overlap   
                else:
                    return [rule0], rule1
        
        elif rule0.is_single():
            if rule0.left == rule1.left:
                out = [PortRange(rule0.left, addrs=rule0.addrs + rule1.addrs)]
                return PortRange(rule0.left+1, rule1.right, list(rule1.addrs))
            else:
                return [rule0], rule1
        else:
            if rule0.left == rule1.left:
                out = [PortRange(rule0.left, addrs=rule0.addrs + rule1.addrs)]
                return PortRange(rule0.left+1, rule0.right, list(rule1.addrs))
            elif rule1.left < rule0.right:
                out = []
                out.append(PortRange(rule0.left, rule1.left-1, list(rule0.addrs)))
                out.append(PortRange(rule1.left, addrs=rule0.addrs + rule1.addrs))
                return out, PortRange(rule1.left+1, rule0.right, list(rule0.addrs))
            elif rule1.left == rule0.right:
                out = [PortRange(rule0.left, rule0.right-1, list(rule0.addrs))]
                return out, PortRange(rule1.left, addrs=rule0.addrs+rule1.addrs)
            else:
                return [rule0], rule1

class PortRange(object):

    def __init__(self, left, right=None, addrs=[]):
        self.left = left
        self.right = right
        self.addrs = addrs

    # Returns true if given port is within this Port Range
    def contains_port_in_range(self, port):
        if self.is_single():
            return self.left == port.left
        else:
            return self.left <= port.left <= self.right

    # Returns True if given address is valid in this port range
    def contains_address_in_range(self, addr):
        i = bisect.bisect_right(self.addr_lbounds, addr)
        if i:
            closest_addr = self.addrs[i-1]
            if len(closest_addr) == 1:
                return addr == closest_addr[0]
            else:
                return closest_addr[0] <= addr <= closest_addr[1]
        return False

    # Returns true if this range is just a single port
    def is_single(self):
        return not self.right or self.left == self.right

    # Create minimum sorted list of addr ranges
    def condense_addrs(self):
        self.addrs.sort(key=lambda x: x[0])

        new_addrs = []
        prev_left, prev_right = None, None

        for addr in self.addrs:
            if len(addr) == 1:
                l, r = addr[0], None
            else:
                l, r = addr

            if not prev_left:
                prev_left, prev_right = l, r
            elif not prev_right:
                if prev_left < l:
                    new_addrs.append((prev_left, prev_left))
                prev_left, prev_right = l, r
            elif prev_right <= l:
                prev_right = max(prev_right, r)
            else:
                new_addrs.append((prev_left, prev_right))
                prev_left, prev_right = None, None

        # Add remainder
        if prev_left:
            if prev_right:
                new_addrs.append((prev_left, prev_right))
            else:
                new_addrs.append((prev_left, prev_left))

        self.addrs = new_addrs
        self.addr_lbounds = [addr[0] for addr in self.addrs]

    # Allows for bisection by left bound value
    def __eq__(self, other):
        return self.left == other.left

    def __gt__(self, other):
        return self.left > other.left

