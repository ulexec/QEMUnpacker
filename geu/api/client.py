import os
import sys
import json
import time
import base64
import requests
import threading
import itertools
from config import output_filename

api_url = "http://127.0.0.1:4321"
done = False

def animate():
    for c in itertools.cycle(['|', '/', '-', '\\']):
        if done:
            sys.stdout.write('\n')
            break
        sys.stdout.write('\r[*] Waiting for analysis ... ' + c)
        sys.stdout.flush()
        time.sleep(0.1)

def main(argv):
    global done

    with open(argv[1], 'rb') as fd:
        file_blob = fd.read()
        
    payload = {
            "file_to_analyze": base64.encodebytes(file_blob),
            "timeout": int(argv[2])
    }

    t = threading.Thread(target=animate).start()
    r = requests.post(url=api_url, json=payload)

    if r.status_code == 200:
        done = True
        time.sleep(.5)

        with open(os.path.join(argv[3], output_filename), 'wb') as fd:
            payload = json.loads(r.text)['payload']
            fd.write(base64.decodebytes(payload.encode('utf-8')))
        print(f'[+] Output collected and saved at {argv[3]}')

if __name__ == '__main__':
    main(sys.argv)
