# Mininet-Programming
EE 555 Mininet Programming in Fall 2019(Used Python)

In this project, we need to bulid a SDN controller. We will be having a dumb/simple packet forwarding switch and an intelligent controller. The dumb packet forwarding switch will be talking to the controller to make forwarding decisions.Based on how we program the controller, the packet forwarding switch will either act as a router or a switch. The controller and the packet forwarding switch will interact with each other using the OpenFlow protocol. We will be using Mininet network emulation software to emulate the testbeds and networks to test and validate the controller and the switch interaction.

There are four scenarios to do.

Scenario 1:

    of_tutorial.py: It is the learning switch controller for Scenario 1.

Scenario 2:
    
    topology2.py: It is the topology for Scenario 2.
    
    controller2.py: It is the controller for Scenario 2.

Scenario 3:

    topology3.py: It is the topology for Scenario 3.
    
    controller3.py: It is the controller for Scenario 3.

Scenario 4: 

    topology4.py: It is the topology for Scenario 4.
    
    controller4.py: It is the controller for Scenario 4.
 
Scenario 1:
In the first scenario, we need to design a controller which function is to act as a layer 2 switch. This scenario gives us the hub function for an example. The hub function is that we need to flood every frame when it goes to the hub. The difference between switch and hub is that we need to use mac to port dictionary to remember every frame’s source mac address when it goes into switch. When some other port wants to send frame, the switch can directly send the frame to that host rather than flooding it. After every flow, we can use msg.match and flow_mod() to install rules in switch. It can increase the bandwidth.

Scenario 2:
In this scenario, we need to design a controller which function is to act as a layer 3 switch and a topology which has 3 hosts in different network. The first thing we need to do is that we need make a connection between host1 and its default router. (IP address: 10.0.1.1)
If the host1 wants to connect with default router, the host will first send the ARP request. We write a function to reply the ARP request and tell the host mac address of default router.
After that, the host will send the ICMP/TCP/UDP request to the router and we need to construct a reply to send to the host. After that, the connection between host and default is over. The next thing is that we need to make a connection between different hosts. Like, we can suppose host1 send packets to host2. (They are in different network) The ARP request and ARP reply is that same. (If we know the mac address of the default router, we do not need ARP request) But in this time, if the switch does not have the host2 mac address, the switch need buffer the packets and send ARP request to ask the mac address of host2. And once we get the mac address of host2, we can pop the packets from the buffer and send the packets to the host2. Host2 will also send ICMP/TCP/UDP reply to host1. And the procedure is the same. From this scenario, we can see that switch is like a transit station. After every flow, we can use msg.match and flow_mod() to install rules in switch. It can increase the bandwidth. And the last thing, if the IP address is not in the static routing table, we need send the unreachable message to the host. We need to care the mac address and port number. If we use the wrong port number, the packets will never send to the right place.

Scenario 3:
In this scenario, we have two layer 3 switches. There is only one thing is different from scenario 2. We need to write a function between s1 and s2. (We use dpid to differentiate the switch) The only thing of the frame we need to change is the mac address. Like, if the host mac address is 00:00:00:00:00:01 and router mac address is aa:bb:cc:dd:ee:01. When the frame is between s1 and s2. The source mac address is aa:bb:cc:dd:ee:01 and destination mac address will be aa:bb:cc:dd:ee:02 which is the mac address of s2. In this case, we need to be care if the packet’s destination IP address is not belonging to the other network, we need to filter it.

Scenario 4:
In this scenario, we have three layer 3 switches. And all these switches formed a loop. But it is almost the same with scenario 3. It is more complex than scenario 3. We also need to filter the packets between different switch to ensure that packets do not get lost in a loop. But other things are the same with scenario 3. We can use the functions that we already wrote. Therefore, it will be very easy.
