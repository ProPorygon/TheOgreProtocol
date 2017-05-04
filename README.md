# TheOgreProtocol
Implementation of onion routing in Python

### Installing
Make sure you have python installed

Clone the repository

`pip install termcolor`

### Running
Run the bare-bones client using:

`python launcher.py [directory authority port] [destination port]`

This is essentially the equivalent of netcat, running over the TOP proxy

Run the proxy client using:

`python launcher-proxy.py [directory authority port] [proxy server port]`

Then setup your web browser to route connections through this port on localhost/127.0.0.1

### Contributors
Kevin Renner

Daniel Schwartz

Carl Remler
