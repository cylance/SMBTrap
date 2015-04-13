# SMBTrap
Tools developed to test the Redirect to SMB issue.  These tools are all developed for Python 2.7.
More details about Redirect to SMB can be found in [our white paper](http://cdn2.hubspot.net/hubfs/270968/SPEAR/RedirectToSMB_public_whitepaper.pdf) and in [our blog](http://blog.cylance.com/redirect-to-smb).


Tools
=====
The tools included in this repository are as follows:
 - smbtrap2.py - A low dependency SMB server which only supports authentication.  It logs authentication attempts, as well as attempts to crack them with a very small dictionary in quickcrack.py
 - redirect_server.py - A very simple Redirect to SMB server which simply provides 302 responses to every HTTP request, which redirect to the SMB server supplied on the command line.
 - smbtrap-mitmproxy-inline.py - A small mitmproxy inline script which replaces functionality for redirect_server.py, allowing for greater flexibility.

Dependencies
============
 - impacket
 - bitarray
 - tornado
 - ntpath