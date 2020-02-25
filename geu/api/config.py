home_path = '/home/intezer'
storage_path = f'{home_path}/geu/data/'
output_filename = 'output.zip'

images = {
    'x86_64' : {
        'run': f'{home_path}/images/x86_64/run.sh',
        'prompt': '# ',
        'rootfs': f'{home_path}/images/x86_64/images/rootfs.ext2'
    },       
     'i386' : {
        'run': f'{home_path}/images/i386/run.sh',
        'prompt': '# ',
        'rootfs': f'{home_path}/images/i386/images/rootfs.ext2'
    }, 
     'aarch64' : {
        'run': f'{home_path}/images/aarch64/run.sh',
        'prompt': '# ',
        'rootfs': f'{home_path}/images/aarch64/images/rootfs.ext2'
    }, 
     'arm' : {
        'run': f'{home_path}/images/arm/run.sh',
        'prompt': '# ',
        'rootfs': f'{home_path}/images/arm/images/rootfs.ext2'
    }, 
    'mips' : {
        'run': f'{home_path}/images/mips/run.sh',
        'prompt': '# ',
        'rootfs': f'{home_path}/images/mips/images/rootfs.ext2'
    }
}

logging_config = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'default': {
            'format':   ('%(asctime)s %(process)s:%(module)s '
                         '[%(levelname)s] - %(message)s'),
            'datefmt': '%Y-%m-%d %H:%M:%S'
        }    
    },
    'handlers': {
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'default',
            'stream': 'ext://sys.stdout'
        }    
    },
    'loggers': {
        '': {
            'level': 'DEBUG',
            'handlers': ['console']
        }
    }
}
