# -*- coding: utf-8 -*-
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread
import json
#from os import curdir, sep

import asyncio

import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class httpApi:
    class myHttpHandler(BaseHTTPRequestHandler):
        def __init__(self, matrix_client, loop, *args):
            self.matrix_client = matrix_client
            self.loop = loop
            logger.info("init")
            BaseHTTPRequestHandler.__init__(self, *args)

        def _set_headers(self):
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()

        def _get_Path(self):
            path = str(self.path)
            path = str(path.split("?")[0])  # argument ignorieren
            pathArray = list(filter(None, path.split("/")))  # remove empty strings
            logger.info("Request " + str(pathArray))
            return pathArray

        def do_GET(self):
            self._set_headers()
            self.wfile.write("received get request")

        def do_POST(self):
            '''Reads post request body'''
            pathArray = self._get_Path()
            self._set_headers()
            if pathArray == ["notify"]:
                content_length = int(self.headers['Content-Length'])  # <--- Gets the size of data
                post_data = self.rfile.read(content_length)  # <--- Gets the data itself
                jsonObj = json.loads(post_data.decode("utf-8"))
                if "msg" in jsonObj:
                    asyncio.run_coroutine_threadsafe(self.matrix_client.send_logMsg(jsonObj['msg']), self.loop)
                else:
                    self.wfile.write("no msg".encode("utf-8"))
                #self.wfile.write("received post request:<br>{}".format(post_body).encode("utf-8"))
            else:
                self.wfile.write("go away " + str(pathArray))

        def do_PUT(self):
            self.do_POST()

    def __init__(self, Matrix_client, loop):
        self.matrix_client = Matrix_client
        self.asyncLoop = loop
        logger.info("start & run thread")
        self.__t = Thread(target=self._serv, args=())
        self.__t.start()

    def stop(self):
        self.httpd.shutdown()

    def _serv(self):
        mclient = self.matrix_client
        loop = self.asyncLoop

        def handler(*args):
            httpApi.myHttpHandler(mclient, loop, *args)

        self.httpd = HTTPServer(("", 8080), handler)
        #httpd.socket = ssl.wrap_socket (httpd.socket,
        #    keyfile="path/to/key.pem",
        #    certfile='path/to/cert.pem', server_side=True)
        self.httpd.serve_forever()
