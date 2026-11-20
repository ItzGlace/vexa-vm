import importlib.util
import json
import os
import subprocess
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import patch
spec = importlib.util.spec_from_file_location('vexa_mcp', Path(__file__).parents[1]/'docs/mcp/vexa_mcp.py')
mcp = importlib.util.module_from_spec(spec); spec.loader.exec_module(mcp)

class MCPTests(unittest.TestCase):
    def test_transport_tls_and_route_boundaries(self):
        for value in ('http://example.com','https://u:p@example.com','https://example.com/x','https://example.com?key=x'):
            with self.assertRaises(ValueError): mcp.base_url(value)
        for path in ('//example.com','/api/v1/auth/login','/api/v1/vms/../admins','/api/v1/vms/%252e%252e','/api/v1/vms/x/password','/api/v1/vms/x/recovery','/api/v1/vms/x/console/keys'):
            with self.assertRaises(ValueError): mcp.safe_path(path)
        self.assertEqual(mcp.safe_path('/api/v1/vms?limit=10'),'/api/v1/vms?limit=10')
    def test_write_opt_in_is_separate_from_confirmation(self):
        with patch.dict(os.environ,{'VEXA_MCP_API_KEY':'local-test-key'},clear=True):
            server=mcp.Server()
            with self.assertRaises(ValueError): server.write_access({'confirmed':True})
            os.environ['VEXA_MCP_ALLOW_WRITES']='1'
            with self.assertRaises(ValueError): server.write_access({'confirmed':False})
            server.write_access({'confirmed':True})
            with self.assertRaises(ValueError): server.call('admin_request',{'method':'GET','path':'/api/v1/vms','extra':True})
    def test_ppm_conversion_and_bounds(self):
        self.assertTrue(mcp.png_image(b'P6\n# comment\n1 1\n255\n\xff\x00\x00').startswith(b'\x89PNG'))
        for value in (b'P6\n9000 1\n255\nx',b'P6\n1 1\n255\nx',b'garbage'):
            with self.assertRaises(ValueError): mcp.png_image(value)
    def test_stdio_uses_authenticated_api_and_does_not_follow_redirects(self):
        seen=[]
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append((self.path,self.headers.get('Authorization')))
                if self.path.endswith('/redirect'):
                    self.send_response(302); self.send_header('Location','http://localhost:1/steal'); self.end_headers(); return
                self.send_response(200); self.send_header('Content-Type','application/json'); self.end_headers(); self.wfile.write(b'{"items":[]}')
            def log_message(self,*args): pass
        http=HTTPServer(('127.0.0.1',0),Handler)
        thread=threading.Thread(target=http.serve_forever,daemon=True); thread.start()
        try:
            environment=dict(os.environ,VEXA_MCP_URL=f'http://127.0.0.1:{http.server_port}',VEXA_MCP_API_KEY='local-test-key')
            requests=[{'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2025-06-18'}}, {'jsonrpc':'2.0','method':'notifications/initialized'}, {'jsonrpc':'2.0','id':2,'method':'tools/list'}, {'jsonrpc':'2.0','id':3,'method':'tools/call','params':{'name':'admin_request','arguments':{'method':'GET','path':'/api/v1/vms'}}}, {'jsonrpc':'2.0','id':4,'method':'tools/call','params':{'name':'admin_request','arguments':{'method':'GET','path':'/api/v1/vms/redirect'}}}]
            run=subprocess.run([sys.executable,str(Path(mcp.__file__))],input='\n'.join(json.dumps(x) for x in requests)+'\n',capture_output=True,text=True,env=environment,check=True)
            results=[json.loads(x) for x in run.stdout.splitlines()]
            self.assertEqual(len(results),4)
            self.assertEqual(len(results[1]['result']['tools']),6)
            self.assertFalse(results[2]['result']['isError'])
            self.assertTrue(results[3]['result']['isError'])
            self.assertEqual(seen,[('/api/v1/vms','Bearer local-test-key'),('/api/v1/vms/redirect','Bearer local-test-key')])
            self.assertNotIn('local-test-key',run.stdout+run.stderr)
        finally: http.shutdown(); http.server_close(); thread.join()
if __name__=='__main__': unittest.main()
