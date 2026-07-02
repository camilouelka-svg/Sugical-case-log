import http.server
import functools

handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory="/Users/camil/Desktop/APPs/simple-app")
httpd = http.server.ThreadingHTTPServer(("0.0.0.0", 8080), handler)
httpd.serve_forever()
