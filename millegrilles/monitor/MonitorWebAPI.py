# Serveur web / API pour le monitor
import logging

from http.server import SimpleHTTPRequestHandler, HTTPServer
from threading import Thread

hostName = "0.0.0.0"
serverPort = 8080


class ServerMonitorHttp(SimpleHTTPRequestHandler):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory='/tmp', **kwargs)

    # def do_GET(self):
    #     path_fichier = self.path
    #     if path_fichier.startswith('/static'):
    #         super().do_GET()
    #     else:
    #         self.send_response(200)
    #         self.send_header("Content-type", "text/html")
    #         self.end_headers()
    #
    #         self.wfile.write(bytes("<html><head><title>https://pythonbasics.org</title></head>", "utf-8"))
    #         self.wfile.write(bytes("<p>Request: %s</p>" % self.path, "utf-8"))
    #         self.wfile.write(bytes("<body>", "utf-8"))
    #         self.wfile.write(bytes("<p>This is an example web server.</p>", "utf-8"))
    #         self.wfile.write(bytes("</body></html>", "utf-8"))

    def do_POST(self):
        path_fichier = self.path
        if path_fichier.startswith('/api'):
            self.send_response(200)
            self.send_header("Content-type", "text/ascii")
            self.end_headers()
            self.wfile.write(bytes("OK", "utf-8"))
        else:
            self.send_response(404)
            self.end_headers()


class ServerWebAPI:

    def __init__(self):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__thread = Thread(name="WebApi", target=self.run)
        self.webServer = None

    def start(self):
        self.__thread.start()

    def run(self):
        self.webServer = HTTPServer((hostName, serverPort), ServerMonitorHttp)
        self.__logger.info("Web API Server started http://%s:%s" % (hostName, serverPort))

        try:
            self.webServer.serve_forever()
        except Exception:
            pass

        self.__logger.info("Web API Server stopped.")

    def server_close(self):
        self.__logger.info("Demande fermeture Web API")
        self.webServer.shutdown()
