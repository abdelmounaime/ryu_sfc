from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.topo import Topo

class TestTopology(Topo):
    def __init__(self):
        Topo.__init__(self)
        host1_id = self.addHost('h1')
        host2_id = self.addHost('h2')
        server_id = self.addHost('server')
        self.addLink(server_id, host1_id)
        self.addLink(server_id, host2_id)

def configure_network(network):
    server = network.get('server')
    server.setIP('10.0.0.10', intf='server-eth0')
    server.setMAC('00:00:00:00:00:10', intf='server-eth0')
    server.setIP('10.0.0.11', intf='server-eth1')
    server.setMAC('00:00:00:00:00:11', intf='server-eth1')
    server.cmd("python -m SimpleHTTPServer 8080 &")

# Run 'sudo python *path_to_this_script*' in mininet VM.
if __name__ == '__main__':
    setLogLevel('info')
    net = Mininet(topo=TestTopology())
    configure_network(net)
    net.pingAll()
    CLI(net)