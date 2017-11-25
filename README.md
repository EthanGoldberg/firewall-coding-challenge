# firewall-coding-challenge
Coding Challenge for Illumio

### How the solution works - (N = size of input):
#### Constructor: - O(N^2 logN) runtime, O(N^2) space
1.	Reads csv, adding rules to one by one to a list based on direction/protocol.  Splits each port range along the way into smallest subranges with correct valid ip address sets. Maintains sorted order - O(N^2) runtime and space
2.	Iterates through all port ranges, condensing ip address sets into largest segments and sorting - O( N^2 logN) worst case runtime

#### Accepting a packet: - O(logN) runtime
1.	Chooses the port range list for the correct direction/protocol. - O(1) runtime
2.	Uses binary search to find nearest left bound for port range.  If the input port is in within that range, gets the corresponding list of valid ip addresses. - O(logN) runtime
3.	Uses binary search to find the nearest left bound for ip address ranges.  If the input ip address is within that range, return True.  Otherwise, return False. - O(logN) runtime

### More Info:
#### My choices:
I chose to prioritize runtime in accepting a packet without compromising space confines.  While maintaining a validity table for all possible inputs could hypothetically run in constant time, it would require an unreasonable amount of space, especially given a rule that spans the full range of port/ip values.  My constructor builds a list of sorted port ranges, each with corresponding lists of sorted ip ranges.  As such, the size of the data structure scales (at worst, at O(N^2)) with the size of the input values rather than with the full range of possible inputs.  Meanwhile, by maintaining a sorted list, the correct values can be indexed logarithmically.

#### What could be improved/changed:
* The current constructor could likely be sped by first sorting the inputs by port range lower bound and then creating the structure in a single iteration rather than by iterating over the full list for each addition.  I did not pursue this avenue because it would be more complex and require significantly more time to code.

* The number of ports is small enough that it may be reasonable to maintain a list of valid ip addresses for each possible port.  This would significantly reduce the cost of finding the correct port, allowing faster runtimes for accepting a packet in many (but not all) cases.  It would also reduce the necessary verbosity and complexity of the code, allowing for easier code maintenance and fewer bugs.

* Another option may be to maintain a binary search tree representing all inputs.  Such a structure could be split based on the value of each bit of rules from highest to lowest order.  The tree may also be pruned to minimize size. This option could hypothetically allow for constant runtime packet acceptances with reasonable size requirements.  I did not choose this method since it was ultimately too complex for me to fully consider and implement in a short amount of time.

### Illumio
I am most interested in the Policy team, but would be excited to work on any of the three teams.
