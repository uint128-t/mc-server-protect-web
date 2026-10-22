from gevent.pywsgi import WSGIServer
import servprotect
import logging
logging.getLogger("werkzeug").disabled = True

server = WSGIServer(("0.0.0.0",10001),servprotect.app,log=None)
server.serve_forever()