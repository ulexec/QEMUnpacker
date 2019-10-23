import os
import sys
import logging.config

from qemu_guest import QEMUGuest
from base import File
from config import logging_config, home_path

logging.config.dictConfig(logging_config)
log = logging.getLogger()

def main(args):
    file_path = args[1]
    data_dir = args[2]
    exec_time = int(args[3])

    log.debug(f'Analyzing {file_path}, {data_dir}, {exec_time}')

    _file = File(file_path, data_dir, exec_time)
    log.debug(f'{_file.arch} {_file.bit} {_file.name}')

    qemu = QEMUGuest(_file)
    log.debug(f'Qemu instance created correctly')

    qemu.start_vm()
    qemu.run_and_analyze(exec_time)
    qemu.extract_output()
    qemu.poweroff_vm()

if __name__ == '__main__':
    if len(sys.argv) != 4:
        print(f'[-] Usage {sys.argv[0]} <file_path>, <data_dir>, <exec_time>')
        sys.exit()
    main(sys.argv)
