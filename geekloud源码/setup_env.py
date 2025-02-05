import os
import re

if 'M2_HOME' not in os.environ:
    # os.environ['M2_HOME'] = '/usr/local/apache-maven-3.8.4'
    os.environ['M2_HOME'] = '/usr/local/apache-maven-3.8.7'
    os.environ['PATH'] = os.path.join(os.environ['M2_HOME'], 'bin') + ':' + os.environ['PATH']

MAVEN_HOME = {
        '3.8.4': '/usr/local/apache-maven-3.8.4',
        '3.5.0': '/usr/local/apache-maven-3.5.0',
        '3.2.5': '/usr/local/apache-maven-3.2.5',
        '3.8.7': '/usr/local/apache-maven-3.8.7',

}

JAVA_HOME = {
        '1.17': '/usr/local/jdk-17.0.6',
        '1.12': '/usr/local/jdk-12',
        # '1.12': '/usr/lib/jvm/jdk-12',
        '1.11': '/usr/local/java-1.11.0-openjdk-amd64',
        '1.9': '/usr/local/jdk-9',
        '1.8': '/usr/local/java-1.8.0-openjdk-amd64',
        '1.7': '/usr/local/java-se-7u75-ri',
        '1.6': '/usr/local/jdk1.6.0_45',
        '1.8': '/usr/local/jdk1.8.0_351'
        }

O_PATH = os.environ['PATH']
CWD = os.getcwd()

def change_cwd(working_dir):
    os.chdir(working_dir)

def recover_cwd():
    os.chdir(CWD)

def change_maven_env(target_version):
    os.environ['M2_HOME'] = MAVEN_HOME[target_version]
    os.environ['PATH'] = os.path.join(os.environ['M2_HOME'], 'bin') + ':' + os.environ['PATH']

def change_java_default():
    change_java_env('1.8')

def change_java_env(target_version):
    os.environ['JAVA_HOME'] = JAVA_HOME[target_version]
    os.environ['PATH'] = os.path.join(os.environ['JAVA_HOME'], 'bin') + ':' + O_PATH

    # for elasticsearch
    if not 'RUNTIME_JAVA_HOME' in os.environ:
        os.environ['RUMTIME_JAVA_HOME'] = JAVA_HOME[target_version]

def current_java_env():
    for k in JAVA_HOME:
        if JAVA_HOME[k] == os.environ['JAVA_HOME']:
            return k
    return 'unknown'
