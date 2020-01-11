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

# Router configurations
info_table = {}
info_table[1] = {'local_IP' : '10.0.1.1', 'local_MAC': 'AA:BB:CC:DD:EE:01', 'local_net': '10.0.1.0/24'}
info_table[2] = {'local_IP' : '10.0.2.1', 'local_MAC': 'AA:BB:CC:DD:EE:02', 'local_net': '10.0.2.0/24'}
info_table[3] = {'local_IP' : '10.0.3.1', 'local_MAC': 'AA:BB:CC:DD:EE:03', 'local_net': '10.0.3.0/24'}

class Router(object):

    def __init__(self, connection):
        log.debug('router is up')

        # Keep track of connection to the switch so that we can send it messages!
        self.connection = connection

        # This binds our PacketIn event listener
        connection.addListeners(self)

        # Switch dipd
        self.dpid = connection.dpid

        # Use this table to keep track of which ethernet address is on
        # which switch port (keys are MACs, values are ports).
        self.mac_to_port = {}

        # ARP cash
        self.arp_cash = {}
        self.arp_cash['10.0.1.1'] = 'AA:BB:CC:DD:EE:01'
        self.arp_cash['10.0.2.1'] = 'AA:BB:CC:DD:EE:02'
        self.arp_cash['10.0.3.1'] = 'AA:BB:CC:DD:EE:03'

        # Buffer the packets if the router does not have the destination MAC address
        self.buffer = {}

        # Router Interface
        self.interface = {}
        self.interface[info_table[self.dpid]['local_IP']] = {'MAC': info_table[self.dpid]['local_MAC'], 'net': info_table[self.dpid]['local_net']}

        # Routing table to the router ip address(It is static)
        self.routing_table_ip = {}
        self.routing_table_ip['10.0.1.2'] = '10.0.1.1'
        self.routing_table_ip['10.0.1.3'] = '10.0.1.1'
        self.routing_table_ip['10.0.1.4'] = '10.0.1.1'
        self.routing_table_ip['10.0.2.2'] = '10.0.2.1'
        self.routing_table_ip['10.0.2.3'] = '10.0.2.1'
        self.routing_table_ip['10.0.2.4'] = '10.0.2.1'
        self.routing_table_ip['10.0.3.2'] = '10.0.3.1'
        self.routing_table_ip['10.0.3.3'] = '10.0.3.1'
        self.routing_table_ip['10.0.3.4'] = '10.0.3.1'
        self.routing_table_ip['10.0.1.1'] = '10.0.1.1'
        self.routing_table_ip['10.0.2.1'] = '10.0.2.1'
        self.routing_table_ip['10.0.3.1'] = '10.0.3.1'

        # Routing table to the port(It is static)
        self.routing_table_port = {}
        self.routing_table_port['10.0.1.2'] = 1
        self.routing_table_port['10.0.1.3'] = 2
        self.routing_table_port['10.0.1.4'] = 3
        self.routing_table_port['10.0.2.2'] = 1
        self.routing_table_port['10.0.2.3'] = 2
        self.routing_table_port['10.0.2.4'] = 3
        self.routing_table_port['10.0.2.1'] = 4
        self.routing_table_port['10.0.3.2'] = 1
        self.routing_table_port['10.0.3.3'] = 2
        self.routing_table_port['10.0.3.4'] = 3
        self.routing_table_port['10.0.3.1'] = 4


        # Routing table to the router port(It is static)
        self.routing_table_router_port = {}
        self.routing_table_router_port['10.0.1.1'] = {'10.0.2.1': 4, '10.0.3.1': 5}
        self.routing_table_router_port['10.0.2.1'] = {'10.0.1.1': 4, '10.0.3.1': 5}
        self.routing_table_router_port['10.0.3.1'] = {'10.0.1.1': 4, '10.0.2.1': 5}

        # Install the route default flow
        for dest in self.arp_cash.keys():
            msg = of.ofp_flow_mod()
            msg.priority = 100
            msg.match.dl_type = ethernet.IP_TYPE
            msg.match.nw_dst = IPAddr(dest)
            msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
            self.connection.send(msg)

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
        log.debug('Network %s ARP frame is going to process' % self.dpid)

        # Check the frame is or not the ARP request
        if  packet.payload.opcode == arp.REQUEST:
            arp_dst_ip = str(packet.payload.protodst)
            log.debug('This is netwrok %s ARP request' % self.dpid)

            # Check the frame is for the hosts or default router
            if arp_dst_ip in self.interface:
                log.debug('This is netwrok %s ARP request for the router gateway' % self.dpid)
                self.ARP_Request_Gateway(packet, packet_in)
            else:
                log.debug('This is network %s ARP request for the router interface' % self.dpid)
                self.ARP_Request_Interface(packet, packet_in)
                           	
        # Check the frame is or not the ARP reply
        if packet.payload.opcode == arp.REPLY:
            log.debug('This is netwrok %s ARP reply' % self.dpid)
            self.ARP_Reply(packet, packet_in)

    def ARP_Request_Interface(self, packet, packet_in):
        self.resend_packet(packet_in, of.OFPP_ALL)
        log.debug('Netwrok %s ARP request has flooded to other sports' % self.dpid)

    def ARP_Request_Gateway(self, packet, packet_in):
        arp_reply = arp()
        arp_reply.opcode = arp.REPLY
        arp_reply.hwsrc = EthAddr(self.interface[str(packet.payload.protodst)]['MAC'])
        arp_reply.hwdst = packet.payload.hwsrc
        arp_reply.protosrc = packet.payload.protodst
        arp_reply.protodst = packet.payload.protosrc
        ether_packet = ethernet()
        ether_packet.type = ether_packet.ARP_TYPE
        ether_packet.src = EthAddr(self.interface[str(packet.payload.protodst)]['MAC'])
        ether_packet.dst = packet.payload.hwsrc
        ether_packet.payload = arp_reply

        self.resend_packet(ether_packet, packet_in.in_port)
        log.debug('Network %s ARP reply has sent' % self.dpid)

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
            log.debug('ICMP packet has sent')

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
            log.debug('This is an ICMP request')

            # Check the ICMP request is for the local or remote
            if self.routing_table_ip[str(packet.payload.dstip)] == info_table[self.dpid]['local_IP']:

                # Check the ICMP request is for the local hosts or for the local router
                if str(packet.payload.dstip) in self.interface:
                    log.debug('This is an %s ICMP request to the local router' % self.dpid)
                    self.ICMP_Request_Router_local(packet, packet_in)
                else:
                    log.debug('This is an %s ICMP request to the local host' % self.dpid)
                    self.ICMP_Request_Host(packet, packet_in)
            else:

                # Check the ICMP request is for the remote hosts or for the remote router
                if str(packet.payload.dstip) == self.routing_table_ip[str(packet.payload.dstip)]:
                    log.debug('This is an %s ICMP request to the remote router' % self.dpid)
                    self.ICMP_Request_Router(packet, packet_in)
                else:
                    log.debug('This is an %s ICMP request to the remote hosts' % self.dpid)
                    self.ICMP_Request_Router(packet, packet_in)                   

        # Check the ICMP packet is or not reply
        if packet.payload.payload.type == 0:

            # Check the ICMP reply is for the router or for the host
            if self.routing_table_ip[str(packet.payload.dstip)] == info_table[self.dpid]['local_IP']:
                self.ICMP_Request_Host(packet, packet_in)
            else:
                self.ICMP_Request_Router(packet, packet_in)

    def ICMP_Request_Router_local(self, packet, packet_in):
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
        log.debug('ICMP/TCP/UDP reply has sent')

    def ICMP_Request_Router(self, packet, pakcet_in):
        src_ip = str(packet.payload.srcip)
        dst_ip = str(packet.payload.dstip)

        packet.src = EthAddr(self.arp_cash[self.routing_table_ip[src_ip]])
        packet.dst = EthAddr(self.arp_cash[self.routing_table_ip[dst_ip]])

        self.resend_packet(packet, self.routing_table_router_port[self.routing_table_ip[src_ip]][self.routing_table_ip[dst_ip]])
        log.debug('ICMP/TCP/UDP packet has sent')

    def ICMP_Request_Host(self, packet, packet_in):
        dst_ip = str(packet.payload.dstip)
        outPort = self.routing_table_port[dst_ip]

        # Check the arp_cash has or not has destination address
        if dst_ip in self.arp_cash:
            packet.src = EthAddr(self.arp_cash[self.routing_table_ip[dst_ip]])
            packet.dst = EthAddr(self.arp_cash[dst_ip])

            self.resend_packet(packet, outPort)
            log.debug('ICMP/TCP/UDP packet has sent')

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

    def TCP_Process(self, packet, packet_in):
        if self.routing_table_ip[str(packet.payload.dstip)] == info_table[self.dpid]['local_IP']:
            self.ICMP_Request_Host(packet, packet_in)
        else:
            self.ICMP_Request_Router(packet, packet_in)

    def _handle_PacketIn (self, event):
            """
            Handles packet in messages from the switch.
            """
            packet = event.parsed # This is the parsed packet data.

            if not packet.parsed:
                log.warning("Ignoring incomplete packet")
                return

            packet_in = event.ofp # The actual ofp_packet_in message.

            # If the frame is LLTP, retrun
            if packet.type == ethernet.LLDP_TYPE:
                log.warning("Ignoring LLDP")
                return 

            # Check this frame is or not for the network
            if packet.type == ethernet.ARP_TYPE:
                if self.routing_table_ip[str(packet.payload.protodst)] != info_table[self.dpid]['local_IP']:
                    return

            # Comment out the following line and uncomment the one after
            # when starting the exercise.
            # self.act_like_hub(packet, packet_in)
            log.debug('Deals with packets from %s to %s' % (packet.src, packet.dst))

            # Add the MAC address to the mac_to_port dictionary
            if str(packet.src) not in self.mac_to_port:
                log.debug('Add %s -> %d into mac_to_port' % (packet.src, packet_in.in_port))
                self.mac_to_port[str(packet.src)] = packet_in.in_port

            # Check the frame destination is or not in the router
            if str(packet.dst) in self.mac_to_port:
                self.resend_packet(packet, self.mac_to_port[(str(packet.dst))])
                log.debug('The network %s frame is to the local hosts' % self.dpid)
            else:

                # Check the ethernet frame is or not an ARP frame
                if packet.type == ethernet.ARP_TYPE:
                    log.debug('This network %s frame is an ARP frame' % self.dpid)
                    self.ARP_Process(packet, packet_in)

                # Check the ethernet frame is or not an IP frame 
                if packet.type == ethernet.IP_TYPE:
                    
                    # Check the ethernet frame is an ICMP frame or an TCP/UDP frame
                    if packet.payload.protocol == ipv4.ICMP_PROTOCOL:
                        log.debug('This network %s frame is an ICMP frame' % self.dpid)
                        if str(packet.payload.dstip) not in self.routing_table_ip:
                            log.debug('This network %s packet is not routable' % self.dpid)
                            self.ICMP_Unreachable(packet, packet_in)
                        else:
                            log.debug('This network %s packet is routable' % self.dpid)
                            self.ICMP_Process(packet, packet_in)
                    else:
                        log.debug('This frame is not an ICMP frame')
                        self.TCP_Process(packet, packet_in)

def launch():
    """
    Starts the component
    """
    def start_switch (event):
        log.debug("Controlling %s" % (event.connection,))
        Router(event.connection)
    core.openflow.addListenerByName("ConnectionUp", start_switch)