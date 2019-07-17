from mininet.topo import Topo

class MyTopo(Topo):

    def __init__(self):

        Topo.__init__(self)

        switch  = self.addSwitch('s1')
        host1 = self.addHost('h1')
        host2 = self.addHost('h2')
        host3 = self.addHost('h3')

        self.addLink(host1,switch)
        self.addLink(host2,switch)
        self.addLink(host2,switch)
        self.addLink(host3,switch)

topos = {'mytopo' : (lambda:MyTopo())}
