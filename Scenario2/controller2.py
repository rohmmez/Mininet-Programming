import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
import pox
import struct
import time
from pox.core import core
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.packet.icmp import icmp, echo
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.recoco import Timer
from pox.lib.util import str_to_bool, dpid_to_str
from pox.lib.revent import *

log = core.getLogger()

class Router(object):

    def __init__(self, connection):
        log.debug('router is up')

        # Keep track of connection to the switch so that we can send it messages!
        self.connection = connection

        # This binds our PacketIn event listener
        connection.addListeners(self)

        # Use this table to keep track of which ethernet address is on
        # which switch port (keys are MACs, values are ports).
        self.mac_to_port = {}

        # ARP cash(It has all the MAC address of the router)(keys are IPs, values are MACs)
        self.arp_cash = {}
        self.arp_cash['10.0.1.1'] = 'AA:BB:CC:DD:EE:01'
        self.arp_cash['10.0.2.1'] = 'AA:BB:CC:DD:EE:02'
        self.arp_cash['10.0.3.1'] = 'AA:BB:CC:DD:EE:03'

        # Install the route default flow
        for dest in self.arp_cash.keys():
            msg = of.ofp_flow_mod()
            msg.priority = 100
            msg.match.dl_type = ethernet.IP_TYPE
            msg.match.nw_dst = IPAddr(dest)
            msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
            self.connection.send(msg)

        # Routing table to the port(It is static)
        self.routing_table_port = {}
        self.routing_table_port['10.0.1.100'] = 1
        self.routing_table_port['10.0.2.100'] = 2
        self.routing_table_port['10.0.3.100'] = 3
        self.routing_table_port['10.0.1.1'] = 1
        self.routing_table_port['10.0.2.1'] = 2
        self.routing_table_port['10.0.3.1'] = 3

        #Routing table to the router ip address(It is static)
        self.routing_table_ip = {}
        self.routing_table_ip['10.0.1.100'] = '10.0.1.1'
        self.routing_table_ip['10.0.2.100'] = '10.0.2.1'
        self.routing_table_ip['10.0.3.100'] = '10.0.3.1'
        self.routing_table_ip['10.0.1.1'] = '10.0.1.1'
        self.routing_table_ip['10.0.2.1'] = '10.0.2.1'
        self.routing_table_ip['10.0.3.1'] = '10.0.3.1'

        # Buffer the packets if the router does not have the destination MAC address
        self.buffer = {}

    def resend_packet (self, packet_in, out_port):
        """
        Instructs the switch to resend a packet that it had sent to us.
        "packet_in" is the ofp_packet_in object the switch had sent to the
        controller due to a table-miss.
        """
        msg = of.ofp_packet_out()
        msg.data = packet_in

        # Add an action to send to the specified port
        action = of.ofp_action_output(port = out_port)
        msg.actions.append(action)

        # Send message to switch
        self.connection.send(msg)
        
    def ARP_Process(self, packet, packet_in):
        log.debug('ARP frame is going to process')

        # Check the frame is or not the ARP request
        if  packet.payload.opcode == arp.REQUEST:
            arp_dst_ip = str(packet.payload.protodst)

            if arp_dst_ip in self.arp_cash:
                log.debug('This is an ARP request')
                self.ARP_Request(packet, packet_in)

        # Check the frame is or not the ARP reply
        if packet.payload.opcode == arp.REPLY:
            log.debug('This is an ARP reply')
            self.ARP_Reply(packet, packet_in)

    def ARP_Request(self, packet, packet_in):
        arp_reply = arp()
        arp_reply.opcode = arp.REPLY
        arp_reply.hwsrc = EthAddr(self.arp_cash[str(packet.payload.protodst)])
        arp_reply.hwdst = packet.payload.hwsrc
        arp_reply.protosrc = packet.payload.protodst
        arp_reply.protodst = packet.payload.protosrc
        ether_packet = ethernet()
        ether_packet.type = ether_packet.ARP_TYPE
        ether_packet.src = EthAddr(self.arp_cash[str(packet.payload.protodst)])
        ether_packet.dst = packet.payload.hwsrc
        ether_packet.payload = arp_reply

        self.resend_packet(ether_packet, packet_in.in_port)
        log.debug('ARP reply has sent')

    def ARP_Reply(self, packet, packet_in):
        src_ip = str(packet.payload.protosrc)
        if src_ip not in self.arp_cash:
            self.arp_cash[src_ip] = str(packet.payload.hwsrc)
        if str(packet.payload.hwsrc) not in self.mac_to_port:
            log.debug('Add %s -> %d into mac_to_port' % (packet.payload.hwsrc, packet_in.in_port))
            self.mac_to_port[str(packet.payload.hwsrc)] = packet_in.in_port
        if src_ip in self.buffer.keys():
            icmp_packet = self.buffer[src_ip]
            outPort = self.routing_table_port[src_ip]
            ether_packet = ethernet()
            ether_packet.type = ether_packet.IP_TYPE
            ether_packet.src = EthAddr(self.arp_cash[self.routing_table_ip[src_ip]])
            ether_packet.dst = EthAddr(self.arp_cash[src_ip])
            ether_packet.payload = icmp_packet

            self.resend_packet(ether_packet, outPort)

            msg = of.ofp_flow_mod()
            msg.priority = 10
            msg.match.dl_type = ethernet.IP_TYPE
            msg.match.nw_dst = IPAddr(icmp_packet.dstip)
            msg.actions.append(of.ofp_action_dl_addr.set_src(EthAddr(self.arp_cash[self.routing_table_ip[src_ip]])))
            msg.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr(self.arp_cash[src_ip])))
            msg.actions.append(of.ofp_action_output(port = outPort))
            log.debug('Installing flow:')
            log.debug('From %s to %s' % (icmp_packet.srcip, icmp_packet.dstip))
            self.connection.send(msg) 
            self.buffer.pop(src_ip)  
                     
    def ICMP_Process(self, packet, packet_in):

        # Check the ICMP packet is or not request
        if packet.payload.payload.type == 8:

            # Check the ICMP request is for the router or not for the router
            if self.routing_table_ip[str(packet.payload.dstip)] == str(packet.payload.dstip):
                log.debug('This is an ICMP request to the router')
                self.ICMP_Request_Router(packet, packet_in)
            else:
                log.debug('This is an ICMP request but not to the router')
                self.ICMP_Request_Not(packet, packet_in)

        # Check the ICMP packet is or not reply
        if packet.payload.payload.type == 0:
            log.debug('This is an ICMP reply')
            self.ICMP_Request_Not(packet, packet_in)

    def ICMP_Request_Router(self, packet, packet_in):
        icmp_reply = icmp()
        icmp_reply.code = 0
        icmp_reply.type = 0
        icmp_reply.payload = packet.payload.payload.payload
        ip_reply = ipv4()
        ip_reply.srcip = packet.payload.dstip
        ip_reply.dstip = packet.payload.srcip
        ip_reply.protocol = ipv4.ICMP_PROTOCOL
        ip_reply.payload = icmp_reply
        ether_packet = ethernet()
        ether_packet.type = ethernet.IP_TYPE
        ether_packet.src = packet.dst
        ether_packet.dst = packet.src
        ether_packet.payload = ip_reply
        
        self.resend_packet(ether_packet, packet_in.in_port)
        log.debug('ICMP reply has sent')

    def ICMP_Request_Not(self, packet, packet_in):
        dst_ip = str(packet.payload.dstip)
        outPort = self.routing_table_port[dst_ip]

        # Check the arp_cash has or not has destination address
        if dst_ip in self.arp_cash:
            packet.src = EthAddr(self.arp_cash[self.routing_table_ip[dst_ip]])
            packet.dst = EthAddr(self.arp_cash[dst_ip])

            self.resend_packet(packet, outPort)
            log.debug('ICMP packet has sent')

        # Check the arp_cash has or not has destination address
        if dst_ip not in self.arp_cash:

            # Buffer the packet(keys are the IP address, values are the ICMP pakcet)
            self.buffer[dst_ip] = packet.payload

            # Construct an ARP packet to get the MAC address of destination MAC address
            arp_request_packet = arp()
            arp_request_packet.opcode = arp.REQUEST
            arp_request_packet.protosrc = IPAddr(self.routing_table_ip[dst_ip])
            arp_request_packet.protodst = IPAddr(dst_ip)
            arp_request_packet.hwsrc = EthAddr(self.arp_cash[self.routing_table_ip[dst_ip]])
            arp_request_packet.hwdst = EthAddr('00:00:00:00:00:00')
            ether_packet = ethernet()
            ether_packet.type = ethernet.ARP_TYPE
            ether_packet.src = EthAddr(self.arp_cash[self.routing_table_ip[dst_ip]])
            ether_packet.dst = EthAddr('FF:FF:FF:FF:FF:FF')
            ether_packet.payload = arp_request_packet

            self.resend_packet(ether_packet, outPort)
            log.debug('ARP request has sent')
        
    def ICMP_Unreachable(self, packet, packet_in):
        icmp_reply_unreachable = icmp()
        icmp_reply_unreachable.code = 0
        icmp_reply_unreachable.type = 3
        icmp_reply_unreachable.payload = packet.payload.payload.payload
        ip_reply_unreachable = ipv4()
        ip_reply_unreachable.srcip = packet.payload.dstip
        ip_reply_unreachable.dstip = packet.payload.srcip
        ip_reply_unreachable.protocol = ipv4.ICMP_PROTOCOL
        ip_reply_unreachable.payload = icmp_reply_unreachable
        ether_packet = ethernet()
        ether_packet.type = ethernet.IP_TYPE
        ether_packet.src = packet.dst
        ether_packet.dst = packet.src
        ether_packet.payload = ip_reply_unreachable

        self.resend_packet(ether_packet, packet_in.in_port)
        log.debug('ICMP reply for unreachable packet has sent')

    def TCP_UDP_Process(self, packet, packet_in):
        dst_ip = str(packet.payload.dstip)
        outPort = self.routing_table_port[dst_ip]

        # Check the router has or not has the destination MAC address
        if dst_ip in self.arp_cash:
            packet.src = EthAddr(self.arp_cash[self.routing_table_ip[dst_ip]])
            packet.dst = EthAddr(self.arp_cash[dst_ip])
            self.resend_packet(packet, outPort)
            log.debug('TCP/UDP has sent')

        if dst_ip not in self.arp_cash:

            # Buffer the packet(keys are the IP address, values are the ICMP pakcets)
            self.buffer[dst_ip] = packet.payload

            # Construct an ARP packet to get the MAC address of destination MAC address
            arp_request_packet = arp()
            arp_request_packet.opcode = arp.REQUEST
            arp_request_packet.protosrc = IPAddr(self.routing_table_ip[dst_ip])
            arp_request_packet.protodst = IPAddr(dst_ip)
            arp_request_packet.hwsrc = EthAddr(self.arp_cash[self.routing_table_ip[dst_ip]])
            arp_request_packet.hwdst = EthAddr('00:00:00:00:00:00')
            ether_packet = ethernet()
            ether_packet.type = ethernet.ARP_TYPE
            ether_packet.src = EthAddr(self.arp_cash[self.routing_table_ip[dst_ip]])
            ether_packet.dst = EthAddr('FF:FF:FF:FF:FF:FF')
            ether_packet.payload = arp_request_packet

            self.resend_packet(ether_packet, outPort)
            log.debug('ARP request has sent')

    def _handle_PacketIn (self, event):
        """
        Handles packet in messages from the switch.
        """
        packet = event.parsed # This is the parsed packet data.

        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        packet_in = event.ofp # The actual ofp_packet_in message.

        # Comment out the following line and uncomment the one after
        # when starting the exercise.
        # self.act_like_hub(packet, packet_in)
        log.debug('Deals with packets from %s to %s' % (packet.src, packet.dst))
    
        # Add the MAC address to the mac_to_port dictionary
        if str(packet.src) not in self.mac_to_port:
            log.debug('Add %s -> %d into mac_to_port' % (packet.src, packet_in.in_port))
            self.mac_to_port[str(packet.src)] = packet_in.in_port

        # Check the ethernet frame is or not an ARP frame
        if packet.type == ethernet.ARP_TYPE:
            log.debug('This frame is an ARP frame')
            self.ARP_Process(packet, packet_in)

        # Check the ethernet frame is or not an IP frame 
        if packet.type == ethernet.IP_TYPE:
            
            # Check the ethernet frame is an ICMP frame or an TCP/UDP frame
            if packet.payload.protocol == ipv4.ICMP_PROTOCOL:
                log.debug('This frame is an ICMP frame')
                if str(packet.payload.dstip) not in self.routing_table_ip:
                    log.debug('This packet is not routable')
                    self.ICMP_Unreachable(packet, packet_in)
                else:
                    log.debug('This packet is routable')
                    self.ICMP_Process(packet, packet_in)
            else:
                log.debug('This frame is not an ICMP frame')
                self.TCP_UDP_Process(packet, packet_in)

def launch():
    """
    Starts the component
    """
    def start_switch (event):
        log.debug("Controlling %s" % (event.connection,))
        Router(event.connection)
    core.openflow.addListenerByName("ConnectionUp", start_switch)