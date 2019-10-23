import os
import time
import shutil
import pexpect
import logging.config
import subprocess 

from config import logging_config, home_path, images

logging.config.dictConfig(logging_config)
log = logging.getLogger()

class QEMUGuest():
    def __init__(self, file):
        self._arch = file.arch
        self._bit = int(file.bit)
        self._endian = file.endian
        self._file_name = file.name
        self._file = file
        self._is_running = False
        self._proc = None
        self._fs = None

        if self._arch not in images:
            log.critical('Image for target architecture not present in config')
            return
        
        # fork image
        base_fs = images[self._arch]['rootfs']
        self._fs = f'{self._file.data_dir}/rootfs'
        shutil.copy(base_fs, self._fs)

        # copy elf binary to image
        log.info(f'Copying {file.name} to rootfs.')
        os.system(
                f'{home_path}/geu/bin/e2cp -G 0 -O 0 -P 755 '
                f'{file.path} {self._fs}:/root/{file.name}'
        )

        # copy agent to image
        log.info(f'Copying agent{file.arch} to rootfs.')
        os.system(
                f'{home_path}/geu/bin/e2cp -G 0 -O 0 -P 755 '
                f'{home_path}/geu/bin/agent-{file.arch} {self._fs}:/root/agent'
        )
        
        run = images[self._arch]['run']
        self._run_cmd = f'{run} {self._file.data_dir}/rootfs'
        self._prompt = images[self._arch]['prompt']

    @property
    def is_running(self):
        return self._is_running

    @property
    def process(self):
        return self._proc

    def send_command(self, command):
        if not self._is_running:
            return None
        
        self._proc.sendline(command)
        self._proc.expect(self._prompt)
        return self._proc.before 

    def start_vm(self):
        log.info(
                f'Requested: {self._arch}, {self._bit}-bit, {self._endian} endian'
        )

        self._proc = pexpect.spawnu(
                self._run_cmd, encoding='utf-8', timeout=self._file.exec_time+50
        )

        self._proc.logfile = open(
                f'{self._file.data_dir}/machine.log', 'w', encoding='utf-8'
        )

        #login
        self._proc.expect('login: ')
        self._proc.sendline('root')
        self._proc.expect('[pP]assword: ')
        self._proc.sendline('root')
        self._proc.expect(self._prompt)

        self._is_running = True
    
    def run_and_analyze(self, exec_time):
        log.debug('Starting analysis')
        self.send_command(f'/root/agent {self._file_name} {exec_time}')
        time.sleep(3 + exec_time)

    def poweroff_vm(self):
        self._proc.sendline('poweroff')
        time.sleep(3)
        self._proc.logfile.close()
        self._is_running = False

    def extract_output(self, keep_fs=False):
        process = subprocess.Popen([f'{home_path}/geu/bin/e2ls', 
                                    f'{self._file.data_dir}/rootfs:/root'], 
                                    stdout=subprocess.PIPE)
        out, err = process.communicate()

        for entry in out.split():
            if b'dumped' not in entry:
                continue

            file_name = entry.decode('utf-8')
            extract_dumped = (
                    f'{home_path}/geu/bin/e2cp '
                    f'{self._fs}:/root/{file_name} '
                    f'{self._file.data_dir}/'
            )
            os.system(extract_dumped)

        log.debug('Memory Artifacts have been extracted')

        if not keep_fs:
            os.system(f'rm {self._fs}')



