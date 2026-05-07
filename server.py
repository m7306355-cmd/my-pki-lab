import ssl
import http.server

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain('cert-chain.pem', 'server.key')

server = http.server.HTTPServer(('0.0.0.0', 4443), http.server.SimpleHTTPRequestHandler)
server.socket = context.wrap_socket(server.socket, server_side=True)

print('HTTPS server running at https://localhost:4443')
print('Press Ctrl+C to stop')
server.serve_forever()
