# TheOgreProtocol
This project is a demonstration of onion routing, similar to the TOR protocol.
Fundamentally, the goal of onion routing is to anonymize network traffic. Our implementation
accomplishes this by wrapping outgoing messages in several layers of encryption. The message
is then sent to several relay nodes in succession. Each node "unwraps" one layer of encryption,
which contains only the next node in the route. The final node, or "exit node" sends the 
original message to the server, and the reply is then sent back through the network, where each 
node rewraps the reply with a layer of encryption. Finally, the client removes all the layers
of encryption, revealing the server's response.

A directory authority maintains the protocol. In our implementation, the the directory authority
performs two functions: registering nodes and building routes out of those nodes. Nodes can register
as "relay" nodes or "exit" nodes. In a large implementation of onion routing, exit nodes would be 
subject to a higher level of scrutiny because of their potential to view unencrypted HTTP traffic.

The benefit of onion routing is that each node only knows the identity of its two neighbors in the
network. Our protocol (and the TOR protocol) constructs routes with two relay nodes and one exit 
node to ensure anonymous traffic.

### Installing
1. Make sure you have python installed
2. Clone the repository
3. Install the required python dependencies
	a) $pip install termcolor
	b) $pip install pycrypto


### Running
1. Server
The Ogre Protocol runs on local loopback. Use simplerecv.py as an endpoint for the protocol:
	$python simplerecv.py [portno]

simplerecv will wait for messages on [portno] indefinitely

2. Ogre network
In another terminal window, start up an instance of an Ogre network with launcher.py:
	$python launcher.py [directory authority port] [destination port]

launcher.py starts a directory authority on the specified port, several relay and exit 
nodes, and a client. Provide the the simplerecv port number to connect to the correct server.

Terminal output will be colored as follows:
Activity from directory authority -> green
Traffic from client -> yellow
Traffic from server -> red
Activity from nodes -> blue

Once the simplerecv server and the launcher are run, messages can be sent back and forth between
the client and server. The "hopped forward" and "hopped backward" text show when traffic is moving
through each node in the route.

3. Additional processes
Once the Ogre network is established on local loobpack, additional nodes and clients may be started
indpendently.
	$python node.py [portno] [dir_auth_ip] [dir_auth_port] [--exit]
	$python client.py [dir_auth_ip] [dir_auth_port] [destination_ip] [destination_port]

If you want to set up an Ogre network without the launcher, you will need to start a directory
authority:
	$python directory_authority.py [portno]

Make sure to clean up any python processes that are still running once you have finished using 
The Ogre Protocol.
	$sudo pkill python

4. The Ogre Protocol as HTTP Proxy
Although it was not within the original scope of our project, the ogre protocol can be run as
an HTTP proxy with a web browser. Use proxy_launcher.py to set up a proxy Ogre network.
	$python proxy_launcher.py [directory authority port] [proxy server port]

Then setup your web browser to route connections through [proxy server port] on localhost/127.0.0.1
To do this with firefox, go to settings->advanced->network->connection. Because this team's project
was to create an onion routing protocol and not an HTTP proxy, some of the qualities of a robust
HTTP proxy have not been implemented due to time constraints. Visiting large webpages may crash
the network.

### Contributors
Kevin Renner

Daniel Schwartz

Carl Remler
