from logging import Logger
import os
import re
import sys
import subprocess
import xml.etree.ElementTree as ET

import setup_env
from utils import check_output_and_logging, logger

from database import construct_db_index, parse_db_index

def parse_programming_language(ext):
    if ext == 'java':
        return 'Java'
    elif ext == 'py':
        return 'Python'
    elif ext == 'c':
        return 'C'
    elif ext == 'cpp' or ext == 'cc':
        return 'C++'
    elif ext == 'sh':
        return 'Bash'
    elif ext == 'cs':
        return 'C#'
    else:
        return 'Others'

class Builder:
    def __init__(self, path):
        self.path = path
        raise NotImplemented('Abstract class cannot be used.')

    def build(self):
        raise NotImplemented('Abstract class cannot be used.')

    def parse_dependency(self, database, force_reanalyze=False):
        raise NotImplemented('Abstract class cannot be used.')

    def parse_language(self):
        res = {}
        tot = 0

        for root, dirs, files in os.walk(self.path):
            for fname in files:
                ext = fname.split('.')[-1]
                lang = parse_programming_language(ext) # Get language type based on suffix
                if not lang in res:
                    res[lang] = 0
                res[lang] += 1
                tot += 1

        for lang in res:
            res[lang] /= float(tot) # use explicit case to compatible with python2

        return res

class MavenBuilder(Builder):
    def __init__(self, path):
        self.path = path
        self.type = 'maven'
        self.Java_List =['1.17','1.12','1.11','1.9','1.8','1.7','1.6']
        self.mavennum = 2
        self.javanum = 5

    def _first_alphabet_pos(self, line):  
        s = 0
        for i in line:
            if i.isalpha():
                break
            s += 1
        return s
    
    def build(self):
        pass

    # functions to deal with mvn exceptions
    def _try_unresolved_subproject_dependency(self, loginfo, **kwargs):
        cmdline = kwargs['cmdline']
        
        # we already add 'install' to solve local dependency
        # if still fail, it is not a unresolved subproject dependency 它不是未解决的子项目依赖关系
        if 'install' in cmdline:
            return False

        a_pattern = '([^: ]*:[^: ]*:[^: ]*:[^: ]*)'
        s_pattern = 'Could not resolve dependencies for project ' + a_pattern
        t_patterns = [
                'Could not find artifact ' + a_pattern,
                a_pattern + ' was not found in http',
            ]
        
        loginfo = loginfo.strip().split('\n')
        for line in loginfo[::-1]:
            if '[ERROR]' not in line:
                continue

            res = re.search(s_pattern, line)

            if res is None:
                continue

            s_fullname = res.group(1)
            
            res = None
            for t_pattern in t_patterns:
                res = re.search(t_pattern, line)
                if res is not None:
                    break

            if res is None:
                continue

            t_fullname = res.group(1)

            # the source and its dependency share the same groupId
            # we assume they all in this project
            # so we try to install the project to local repository
            # to get dependency of parents or siblings
            if s_fullname.split(':')[0] == t_fullname.split(':')[0]:
                # we add install option to avoid unresolved local dependency in the same project
                logger.warning("Detect sibling dependency, try to install at first")
                cmdline.insert(0, 'install')
                cmdline.insert(1, '-DskipTests')
                return True

        return False

    def _try_incompatible_java_version(self, loginfo, **kwargs):
        a_pattern = '([^: ]*:[^: ]*:[^: ]*:[^: ]*)'
        pattern = 'Could not find artifact ' + a_pattern

        loginfo = loginfo.strip().split('\n')
        for line in loginfo[::-1]:
            if '[ERROR]' not in line:
                break

            res = re.search(pattern, line)
            if res is None:
                continue

            fullname = res.group(1)

            groupId, artifactId, ext, version = fullname.split(':')
            if groupId.startswith('jdk.'):
                logger.warning("Detect incompatible JDK version")
                logger.warning("Trying to automatically change to %s" % version)
                current_version = setup_env.current_java_env()

                # outdated java not supported, just try 1.8
                if float(version) < 1.65:
                    version = '1.8'
                    logger.warning("version not supported, try %s" % version)

                if current_version == version:
                    logger.error("Already in %s, check other possible reasons!" % current_version)
                    return False
                setup_env.change_java_env(version)

                return True

        return False

    def _try_invalid_target_release(self, loginfo, **kwargs):
        pattern = "invalid target release: ([^ ]*)"

        loginfo = loginfo.strip().split('\n')
        for line in loginfo[::-1]:
            if '[ERROR]' not in line:
                break

            res = re.search(pattern, line)
            if res is None:
                continue

            version = res.group(1)
            logger.warning("Detect invalid target relase: %s" % version)

            # outdated java not supported, just try 1.8
            if float(version) < 1.65:
                version = '1.8'
                logger.warning("version not supported, try %s" % version)

            current_version = setup_env.current_java_env()
            if current_version == version:
                logger.error("Already in %s, check other possible reasons!" % current_version)
                return False
            setup_env.change_java_env(version)

            return True

        return False

    def _try_invalid_protocol_version(self, loginfo, **kwargs):
        cmdline = kwargs['cmdline']

        pattern = "Received fatal alert: protocol_version"

        if '-Dhttps.protocols=TLSv1.2' in cmdline:
            return False

        loginfo = loginfo.strip().split('\n')
        for line in loginfo[::-1]:
            if '[ERROR]' not in line:
                break

            res = re.search(pattern, line)
            if res is None:
                continue

            cmdline.append('-Dhttps.protocols=TLSv1.2')
            return True
        return False

    def _try_ssl_peer_shutdown(self, loginfo, **kwargs):
        cmdline = kwargs['cmdline']

        pattern = "SSL peer shut down incorrectly"

        if '-Dhttps.protocols=TLSv1.2' in cmdline:
            return False

        loginfo = loginfo.strip().split('\n')
        for line in loginfo[::-1]:
            if '[ERROR]' not in line:
                break

            res = re.search(pattern, line)
            if res is None:
                continue

            cmdline.append('-Dhttps.protocols=TLSv1.2')
            return True
        return False

    # 编译错误
    def __try_compilation_failure(self,loginfo):
        pattern = 'Compilation failure'

        loginfo = loginfo.strip().split('\n')
        for line in loginfo[::-1]:
            if '[ERROR]' not in line:
                break

            res = re.search(pattern, line)
            if res is None:
                continue
            # 编译失败可能是java版本也可能是maven版本
            setup_env.change_java_env(self.Java_List[self.javanum])
            if self.javanum ==0:
                # setup_env.change_maven_env('3.8.4')
                setup_env.change_maven_env('3.8.7')
            else:
                self.javanum-=1
            return True
        return False

    # parse dependency by mvn dependency:tree
    def parse_dependency(self, database, force_reanalyze=False):
        repo_path = self.path

        os.chdir(repo_path)

        if not os.path.exists('mvnlog.txt') or force_reanalyze:
            os.system('rm mvnlog.txt')
            # call mvn dependency:tree to resolve dependencies
            cmdline = ['dependency:tree']
            # ignore SSL certificate temporally, but it is better to add it back later
            cmdline += ['-Dmaven.wagon.http.ssl.insecure=true', '-Dmaven.wagon.http.ssl.allowall=true', '-Dmaven.wagon.http.ssl.ignore.validity.dates=true']
            # 跳过  测试：
            cmdline += ['-Dskiptests=true']
            # try and solve handleable exceptions
            while True:
                try:
                    output = check_output_and_logging(['mvn'] + cmdline)
                    break
                except subprocess.CalledProcessError as e:
                    loginfo = e.output.decode()
                    # handleable exceptions
                    if self._try_invalid_protocol_version(loginfo, cmdline=cmdline):
                        continue
                    elif self._try_ssl_peer_shutdown(loginfo, cmdline=cmdline):
                        continue
                    elif self._try_incompatible_java_version(loginfo, cmdline=cmdline):
                        continue
                    elif self._try_unresolved_subproject_dependency(loginfo, cmdline=cmdline):
                        continue
                    elif self._try_invalid_target_release(loginfo, cmdline=cmdline):
                        continue
                    elif self.__try_compilation_failure(loginfo):
                        continue
                    # unknown situations, just raise
                    else:
                        loginfo = loginfo.strip().split('\n')
                        with open('/root/osschain/error_log.txt', 'a', encoding= 'utf-8') as f:
                            f.write(repo_path+':')
                            f.write('\n')
                            for line in loginfo[::-1]:
                                if '[ERROR]' in line:
                                    f.write(line)
                                    f.write('\n')
                        raise e

            with open('mvnlog.txt', 'w') as fout:
                fout.write(output.decode())

        setup_env.recover_cwd()

        with open(os.path.join(repo_path, 'mvnlog.txt'), 'r') as flog:
            status = False
            for line in flog:
                if 'maven-dependency' in line: 
                     #[2023-01-27 01:42:05 INFO] [INFO] --- maven-dependency-plugin:3.1.1:tree (default-cli) @ tez ---
                    stack = [None]
                    status = True
                    continue

                if status:
                    if not line.startswith('[INFO]'):
                        continue
                    # remove the '[INFO]'  
                    line = line[7:]
                    level = self._first_alphabet_pos(line)

                    if not line:
                        status = False
                        continue
                    # 遇到类似“Skipping plugin execution”，并不是个合法的依赖树
                    if not ':' in line:
                        status = False
                        continue
                    # 可能会出现“Configured Artifact”造成这个
                    if 'Configured Artifact' in line:
                        status = False
                        continue
                    # check if pure_name is a valid record, if empty or startswith '---', the record is end
                    if level >= len(line):
                        status = False
                        continue
                    
                    pure_name = line[level:].strip()
                    level //= 3
                    pure_name = pure_name.split(':')

                     # org.apache.tez:hadoop-shim:jar:0.10.3-SNAPSHOT --- /1 //3 ==0
                     # +- org.slf4j:slf4j-api:jar:1.7.36:compile      --- /4 //3 ==1
                     # |  \- org.hamcrest:hamcrest-core:jar:1.3:test  --- /7 //3 ==2
                     # |  |  +- com.google.guava:failureaccess:jar:1.0.1:compile  --- /10 //3 ==3
                    # 其中
                    # “+-”符号表示该包后面还有其它依赖包，
                    # “\-”表示该包后面不再依赖其它jar包
                    
                    scope = ''
                    if level == 0:
                        logger.info(pure_name)
                        group_id, artifact, artifact_type, version = pure_name  
                    else:
                        # deal with 'noaop' flag
                        if len(pure_name) == 6:
                            group_id, artifact, artifact_type, aop_flag, version, scope = pure_name
                            version = version + '-' + aop_flag
                        else:
                            group_id, artifact, artifact_type, version, scope = pure_name

                    db_index = construct_db_index(group_id, artifact, artifact_type, version, scope)

                    if level + 1 < len(stack):
                        for i in range(level, len(stack)):
                            database.write(stack[i], None) # set a None child to mark this artifact has been analyzed
                        # pop the stack before level
                        stack = stack[:level + 1]
                    stack.append(db_index)
                    parent = stack[-2]
                    database.write(parent, db_index) # dependency: parent->db_index

    def get_metadata(self):
        repo_path = self.path
        version = ""
        groupid = ""

        pom = ET.ElementTree(file=os.path.join(self.path, 'pom.xml')) # Load the xml file and return the ElementTree object
        root = pom.getroot() # get the root node
        for ele in root:
            if 'version' in ele.tag: # Element.tag represents the tag of the element object
                version = ele.text
            if 'groupId' in ele.tag:
                groupid = ele.text

        return {'groupId': groupid, 'version': version}

class GradleBuilder(Builder):
    def __init__(self, path):
        self.path = path
        self.type = 'gradle'

        # os.chdir() 用于更改当前工作目录到指定的路径, 使用 os.chdir() 函数可以方便地切换工作目录，从而可以访问不同位置的文件和目录。
        # 切换当前目录到目标组件的目录之下
        os.chdir(self.path)

        # 调用syscall,给当前目录下的 gradlew 文件添加可执行权限。
        os.system('chmod +x ./gradlew')
        setup_env.recover_cwd()
        # setup_env.change_java_env('1.12')
        setup_env.change_java_env('1.17')
        # setup_env.change_java_env('1.8')



    def _get_level(self, line):
        for i in range(len(line)):
            if line[i].isalpha():
                return i // 5

    def _get_project_name_from_line_in_gradledep(self, line):
        _line = line.replace("'", ' ')
        _line = _line.replace('\n', '')
        _line = _line.split(' ')
        project_name = None

        # non-root project must has ':' in its name
        for ele in _line:
            if ':' in ele and ele!=':':
                project_name = ele
                break

        # root project
        if project_name is None:
            project_name = ':'

        return project_name
    
    def _is_line_part_of_deptree(self, line):
        dep_tag = ['+', '|', '\\']
        _line = line.strip()
        if len(_line) > 0 and _line.strip()[0] in dep_tag:
            return True
        return False

    def build(self):
        pass

    def parse_dependency(self, database, force_reanalyze=False):
        repo_path = self.path
        artifacts = {}

        os.system('cp getattr.gradle ' + repo_path)
        os.chdir(repo_path)

        # step1: parse all project names
        if not os.path.exists('gradlelog.txt') or force_reanalyze:
            # before reanalyze, clean cache
            os.system('rm gradlelog.txt')

            output = check_output_and_logging(['./gradlew', '--init-script=./getattr.gradle', 'getProjectAttr']).decode()
            with open('gradlelog.txt', 'w') as fout:
                fout.write(output)

        # step2: make up artifact dict {projectName: [artifact1, artifact2]}
        with open('./gradlelog.txt', 'r') as fin:
            lines = fin.read()
            lines = lines.split('<========>\n')[1:-1]
            # for each gradle project
            for i, line in enumerate(lines):
                line = line.split('--------\n')
                projectName = line[0].strip().strip('\n')
                line = line[1:]
                artifacts[projectName] = []

                # skip projects with no artifacts
                if len(line) == 0:
                    continue

                # get all artifacts in the project
                for artifact in line:
                    groupId, artifactId, fileExt, version = artifact.split('\n')[:4]
                    artifacts[projectName].append(':'.join([artifactId, groupId, fileExt, version]))

        # stpe3: get dependency tree via gradlew api
        if not os.path.exists('./gradledep.txt') or force_reanalyze:
            os.system('rm gradledep.txt')

            for projectName in artifacts:
                print("projectName:",projectName)
                if(projectName==':'):
                    output = check_output_and_logging(['./gradlew','-x','test','%sdependencies' % projectName])
                else:
                    output = check_output_and_logging(['./gradlew','-x','test','%s:dependencies' % projectName])
                # output = check_output_and_logging(['./gradlew','-x','test','%s:dependencies' % projectName])

                
                with open('./gradledep.txt', 'a') as fout:
                    fout.write(output.decode())

        # step4: construct dependency tree
        stack = [None]
        with open('./gradledep.txt', 'r') as fin:
            project_name = None
            project_flag = False
            for line in fin:
                if line[0] == '-':
                    project_flag = not project_flag
                    continue

                # when find a new project, clean stack
                if project_flag:

                    project_name = self._get_project_name_from_line_in_gradledep(line)

                    stack = [artifacts[project_name]]

                # we find a project, then we parse its dependencies
                if project_name and not project_flag:
                    if self._is_line_part_of_deptree(line):
                        level = self._get_level(line)
                        artifact_name = line[level * 5:]

                        # broken dependency, just ignore
                        if artifact_name.startswith('unspecified'):
                            continue
                        # depend on sub project
                        elif artifact_name.startswith('project'):
                            subproject = artifact_name.split(' ')[1].strip()

                            # sometimes, subproject will omit ':' in the beginning
                            # most cases: 'project :logstash-core'
                            # sometimes:   'project logstash-core'
                            # just add ':' doesn't work, sometimes it is ambiguous
                            # for example
                            # 'project api' in 'kafka:storage' dependencies
                            # but in the project, there are ':client:api' and ':storage:api'
                            # so it is not clear what the 'api' is
                            # we just skip it
                            if subproject[0] != ':':
                                continue
                                # subproject = ':' + subproject

                            artifact = artifacts[subproject]
                        # depend on external artifact
                        else:
                            logger.info("aritfact name:"+artifact_name)
                            # 出现 -> 的情况，要做个处理
                            try:
                                if("strictly" in artifact_name):
                                    group_id, artifact_id, version = artifact_name.strip().split(' -> ')[0].split(':')
                                else:
                                    group_id, artifact_id, version = artifact_name.strip().split(' ')[0].split(':')
                            except ValueError:
                                if re.search('->',artifact_name):
                                    artifact_name = artifact_name.replace(' -> ',':')
                                    group_id, artifact_id, version = artifact_name.strip().split(' ')[0].split(':')
                            artifact = [':'.join([group_id, artifact_id, 'jar', version])]

                        # var artifact is a list of artifacts
                        # if current element is an externel dependency, artifact list will include a single artifact
                        # if current element is a subproject, artifact list will include all artifacts in this project
                        if len(stack) > level:
                            stack = stack[:level]
                        stack.append(artifact)

                        for parent in stack[-2]:
                            for child in stack[-1]:
                                database.write(parent, child)

        setup_env.recover_cwd()
    
    def get_metadata(self):
        data = {}

        os.system('cp getattr.gradle ' + self.path)
        os.chdir(self.path)
        try:
            output = check_output_and_logging(['./gradlew', '--init-script=./getattr.gradle', 'getMetadata']).decode().split('\n')
        except subprocess.CalledProcessError as e:
            # setup_env.change_java_env('1.17') #需要改吗？
            setup_env.change_java_env('1.8') #需要改吗？
            output = check_output_and_logging(['./gradlew', '--init-script=./getattr.gradle', 'getMetadata']).decode().split('\n')

        with open('./metadata.txt', 'w') as fout:
                fout.write(str(output))
        
        setup_env.recover_cwd() # Return to the current working directory

        group_flag = False
        ver_flag = False
        for line in output:
            if '[GROUP]' in line:
                group_flag = True
                continue

            if group_flag:
                data['groupId'] = line.strip()
                group_flag = False
                continue

            if '[VERSION]' in line:
                ver_flag = True
                continue

            if ver_flag:
                data['version'] = line.strip()
                ver_flag = False
                continue

        return data

class AntBuilder(Builder):
    def __init__(self, path):
        self.path = path
        self.type = 'ant'

    def build(self):
        pass

    def parse_dependency(self, database, force_reanalyze=False):
        pass

    def get_metadata(self):
        pass

def get_builder(path):
    #因为gradle和maven都属于依赖管理的方式，一般有一个就没有另一个了，你可以在Github上找带有pom的仓库
    if os.path.exists(os.path.join(path, 'pom.xml')):
        return MavenBuilder(path)
    elif os.path.exists(os.path.join(path, 'gradlew')):
        return GradleBuilder(path)
    elif os.path.exists(os.path.join(path, 'build.xml')):
        return AntBuilder(path)

