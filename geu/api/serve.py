import os
import sys
import json
import base64
import logging.config
import zipfile

from base import File
from shutil import rmtree
from qemu_guest import QEMUGuest
from config import logging_config, home_path, storage_path, output_filename
from http.server import BaseHTTPRequestHandler
from http.server import HTTPServer
from urllib.parse import urlparse, parse_qs

logging.config.dictConfig(logging_config)
log = logging.getLogger()

def zipdir(path, ziph):
    for root, dirs, files in os.walk(path):
        for file in files:
            ziph.write(os.path.join(root, file))

class HTTPHandler(BaseHTTPRequestHandler):
    def _set_response(self, response_code, response):
        self.send_response(response_code)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(response.encode(encoding='utf_8'))

    def do_POST(self):
        content_lenght = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_lenght)
        parsed_request = json.loads(post_data)

        if not parsed_request.get('file_to_analyze') or \
            not parsed_request.get('timeout'):
            log.debug('Invalid post request received')

            response = {
                'succeeded': 'false',
                'payload': 'None'      
            }
            self._set_response(404, json.dumps(response))

        else:
            file_blob = parsed_request.get('file_to_analyze')
            timeout = parsed_request.get('timeout')
            
            if not os.path.exists(storage_path):
                os.makedirs(storage_path)

            file_path = os.path.join(storage_path, 'file_to_analyze')
            with open(file_path, 'wb') as fd:
                fd.write(base64.decodebytes(file_blob.encode('utf-8')))

            log.debug(f'Analyzing {file_path}, {storage_path}, {timeout}')

            _file = File(file_path, storage_path, timeout)
            log.debug(f"{_file.arch} {_file.bit} {_file.name}")

            qemu = QEMUGuest(_file)
            os.remove(file_path)
            log.debug(f'Qemu instance created correctly')
            

            qemu.start_vm()
            qemu.run_and_analyze(timeout)
            qemu.poweroff_vm()
            qemu.extract_output()

            log.debug(f'Ziping directory {storage_path}')
            zipf = zipfile.ZipFile('output.zip', 'w', zipfile.ZIP_DEFLATED)
            zipdir(storage_path, zipf)
            zipf.close()

            with open(output_filename, 'rb') as fd:
                output_data = base64.encodebytes(fd.read())

            response = {
                'succeeded': 'true',
                'payload': output_data.decode('utf-8')
            }
            self._set_response(200, json.dumps(response))
            rmtree(storage_path)


if __name__ == '__main__':
    httpd = HTTPServer(('0.0.0.0', int(sys.argv[1])), HTTPHandler)
    log.info('Serving at 0.0.0.0 : %d ' % int(sys.argv[1]))
    httpd.serve_forever()
