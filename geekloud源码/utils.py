import sys
import logging
import subprocess
import os
import json

logging.basicConfig(level=logging.INFO,
        format='[%(asctime)s %(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S')

logger = logging.getLogger()

def check_output_and_logging(*popenargs, **kwargs):
    process = subprocess.Popen(*popenargs, stdout=subprocess.PIPE, **kwargs)
    logger.info(str(popenargs))
    output = b''
    for line in iter(process.stdout.readline, b''):
        logger.info(line.decode().replace('\n', ''))
        output += line
    process.stdout.close()

    retcode = process.wait()
    if retcode != 0:
        raise subprocess.CalledProcessError(retcode, process.args, output=output)

    return output

def mkdir(path):
    if not os.path.exists(path):
        os.makedirs(path)


METADATA_DEPENDENCY_FORMAT = 1
NODES_LINKS_FORMAT = 2
NONE_FORMAT = 0

def GeekLoud_format_By_File(SBOM_file):
    with open(SBOM_file,'r',encoding='UTF-8') as f:
        data = json.load(f)
    if 'nodes' and 'links' in data:
        # print('nodes-links format')
        return NODES_LINKS_FORMAT
    if 'metadata' and 'dependency' in data:
        return METADATA_DEPENDENCY_FORMAT
    return NONE_FORMAT

def GeekLoud_format_By_Data(SBOM):
    if 'nodes' and 'links' in SBOM:
        return NODES_LINKS_FORMAT
    if 'metadata' and 'dependency' in SBOM:
        return METADATA_DEPENDENCY_FORMAT
    return NONE_FORMAT
 
