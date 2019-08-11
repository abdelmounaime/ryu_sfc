from mininet.topo import Topo
from mininet.link import Link, TCLink

class MyTopo(Topo):
    def __init__(self):
        Topo.__init__(self)
        host1 = self.addHost('h1')
        host2 = self.addHost('h2')
        #host2.cmd('ifconfig h2-eth1 10.1.1.10 netmask 255.255.255.0')
        host3 = self.addHost('h3')
        switch = self.addSwitch('s1')

        #Link(host2, switch,intfName1='h2-eth1')

        self.addLink(host1,switch)
        self.addLink(host2,switch)
        self.addLink(host2,switch)
        self.addLink(host3,switch)

topos={'mytopo':(lambda: MyTopo())}
