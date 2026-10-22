from gevent.pywsgi import WSGIServer
import servprotect
import logging
logging.getLogger("werkzeug").disabled = True

server = WSGIServer(("0.0.0.0",servprotect.config.WEB_PORT),servprotect.app,log=None)
server.serve_forever()