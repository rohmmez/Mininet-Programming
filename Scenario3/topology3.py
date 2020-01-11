from mininet.topo import Topo

class Topology3( Topo ):

    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )

        # Add hosts
        host3 = self.addHost( 'h3', ip="10.0.1.2/24", defaultRoute = "via 10.0.1.1" )
        host4 = self.addHost( 'h4', ip="10.0.1.3/24", defaultRoute = "via 10.0.1.1" )
        host5 = self.addHost( 'h5', ip="10.0.2.2/24", defaultRoute = "via 10.0.2.1" )

        # Add switch
        switch1 = self.addSwitch('s1')
        switch2 = self.addSwitch('s2')        

        # Add links
        self._links = self.addLink(host3, switch1)
        self._links = self.addLink(host4, switch1)
        self._links = self.addLink(host5, switch2)
        self._links = self.addLink(switch1, switch2)

topos = {'topology3' : (lambda: Topology3())}
