import logging
from logging.handlers import RotatingFileHandler
import datetime
import os
import sys
import json
import argparse

import builder
import database
import setup_env
from utils import logger, check_output_and_logging
import utils
import geekloud2cydx
import geekloud2spdx
import cydx2geekloud
import spdx2geekloud
import geek_transfer
import analysis_tools

# def mkdir(path):
#     if not os.path.exists(path):
#         os.makedirs(path)



def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--action', default='None', help='do something')
    parser.add_argument('--taskid', default='None', help='taskid')
    parser.add_argument('--depth', default=3, help='max dependency depth')
    parser.add_argument('--verbose',action='store_true',default=False,help="whether output for 'nodes-links' format?")
    parser.add_argument('--srcType',default=None)
    parser.add_argument('--tarType',default=None)
    parser.add_argument('--srcSBOM',default=None,help='the src SBOM file')
    parser.add_argument('--tarSBOM',default=None,help='the compared SBOM file')
    parser.add_argument('--output',default='output.json',help='the output')

    args = parser.parse_args()
    args.depth = int(args.depth)
    return args

def dependency(args):
    if args.taskid == 'None':
        logger.error('Taskid is needed for action dependency')
        return
    # path = os.path.join('/root/osschain/task', args.taskid) # Repository Address
    path = args.taskid
    if not os.path.exists(path):
        logger.error('Taskid %s does not exist.' % args.taskid)
        return

    # set environment
    setup_env.change_java_default()

    logger.info(os.environ['JAVA_HOME'])

    # create a dict database
    db = database.get_database(database.DB_TYPE_DICT)

    # get builder
    bdr = builder.get_builder(path)
    if bdr == None:
        logger.error('There is no pom.xml, gradlew and build.xml in the repository!')
    # get groupid and version
    metadata = bdr.get_metadata()
    if metadata == None:
        logger.error("There is build.xml in the repository! But it hasn't been dealt with yet!")
    metadata['builder'] = bdr.type
    group_id = metadata['groupId']

    # get dependency
    bdr.parse_dependency(database=db, force_reanalyze=True)
    dependency, ndeps, stats = db.query(group_id, max_depth=args.depth)

    # count multi-level dependencies
    metadata['n_dep'] = ndeps
    metadata['d_dep'] = args.depth
    metadata['n_art'], metadata['level1'], metadata['level2'], metadata['level3'] = stats

    metadata['language'] = bdr.parse_language()

    data = {'metadata': metadata, 'dependency': dependency}
    
    if args.verbose == True:
        data = geek_transfer.transfer(data)
    
    # print(json.dumps(data, indent=4), file=sys.stdout)
    
    # with open(args.output,'w',encoding='UTF-8') as f:
    #     print(json.dumps(data, indent=4), file=f)
    return data




################################


Valid_SBOM_format = ['cyclonedx','spdx','geek']

def is_Src_and_TarType_Valid(args):
    if args.srcType not in Valid_SBOM_format:
        logger.error(f"source SBOM format is not legal for {args.action}")
        return False
    if args.tarType not in Valid_SBOM_format:
        logger.error(f"target SBOM format is not legal for {args.action}")
        return False
    return True

def is_SrcSBOM_Valid(args):
    if args.srcSBOM == None:
        logger.error(f"srcSBOM is needed for action {args.action}")
        return False
    # if 'json' not in args.srcSBOM:
    #     logger.error('srcSBOM file is not json file') 
    #     return False
    if not os.path.exists(args.srcSBOM):
        logger.error('srcSBOM %s does not exist.' % args.srcSBOM)
        return False
    return True


def is_TarSBOM_Valid(args):
    if args.tarSBOM == None:
        logger.error(f"tarSBOM is needed for action {args.action}")
        return False
    # if 'json' not in args.srcSBOM:
    #     logger.error('tarSBOM file is not json file') 
    #     return False
    if not os.path.exists(args.tarSBOM):
        logger.error('tarSBOM %s does not exist.' % args.tarSBOM)
        return False
    return True


def isFileValid(file,action,attrName):
    if file == None:
        logger.error(f"{attrName} is needed for action {action}")
        return False
    # if 'json' not in file:
    #     logger.error(f'{attrName} file is not json file') 
    #     return False
    if not os.path.exists(file):
        logger.error(f'{attrName} %s does not exist.' % file)
        return False
    return True



################################


def compare(args):
    if not is_Src_and_TarType_Valid(args):
        return
    if args.srcType == args.tarType:
        logger.error(f'source SBOM TYPE can not be the same as target SBOM TYPE for {args.action}')
        return 
    if not is_SrcSBOM_Valid(args):
        return 
    if not is_TarSBOM_Valid(args):
        return
    # if args.verbose == None:
    #     logger.error(f'verbose is needed for action {args.action}')
    #     return 
    srcType = args.srcType
    tarType = args.tarType
    if srcType == "geek" and tarType == 'cyclonedx':
        format = utils.GeekLoud_format_By_File(args.srcSBOM)
        if format == utils.NODES_LINKS_FORMAT:
            result = analysis_tools.analysis_by_File_and_File(args.srcSBOM, args.tarSBOM)
            # print(result)
        else:
            if format == utils.METADATA_DEPENDENCY_FORMAT:
                geek2 = geek_transfer.transfer_by_File(args.srcSBOM)
                result = analysis_tools.analysis_by_Data_and_File(geek2,args.tarSBOM)
            else:
                logger.error(f"Geekloud's format is not legal for action {args.action}")
                return
    if srcType == 'cyclonedx' and tarType == 'geek':
        format = utils.GeekLoud_format_By_File(args.tarSBOM)
        if format == utils.NODES_LINKS_FORMAT:
            result = analysis_tools.analysis_by_File_and_File(args.tarSBOM, args.srcSBOM)
        else:
            if format == utils.METADATA_DEPENDENCY_FORMAT:
                geek2 = geek_transfer.transfer_by_File(args.tarSBOM)
                result = analysis_tools.analysis_by_Data_and_File(geek2,args.srcSBOM)
            else:
                logger.error(f"Geekloud's format is not legal for action {args.action}")
                return
    if srcType == 'geek' and tarType == 'spdx':
        middle2 = spdx2geekloud.transferFunc(args.tarSBOM)
        # middle2 = geekloud2cydx.transferFunc_By_Data(middle2)
        format = utils.GeekLoud_format_By_File(args.srcSBOM)
        if format == utils.NODES_LINKS_FORMAT:
            # result = analysis_tools.analysis_by_File_and_Data(args.srcSBOM,middle2)
            logger.error('topic geekloud SBOM format is needed in comparation between geek and spdx')
            return
        else:
            if format == utils.METADATA_DEPENDENCY_FORMAT:
                # middle1 = geek_transfer.transfer_by_File(args.srcSBOM)
                # result = analysis_tools.analysis_by_Data_and_Data(middle1,middle2)
                middle1 = geekloud2cydx.transferFunc(args.srcSBOM)
                middle2 = geek_transfer.transfer(middle2)
                result = analysis_tools.analysis_by_Data_and_Data(middle2,middle1)
            else:
                logger.error(f"Geekloud's format is not legal for action {args.action}")
                return 
    if srcType == 'spdx' and tarType == 'geek':
        middle2 = spdx2geekloud.transferFunc(args.srcSBOM)
        # return middle2
        # middle2 = geekloud2cydx.transferFunc_By_Data(middle2)
        format = utils.GeekLoud_format_By_File(args.tarSBOM)
        if format == utils.NODES_LINKS_FORMAT:
            logger.error('topic geekloud SBOM format is needed in comparation between geek and spdx')
            return
            # result = analysis_tools.analysis_by_File_and_Data(args.tarSBOM,middle2)
        else:
            if format == utils.METADATA_DEPENDENCY_FORMAT:
                # middle1 = geek_transfer.transfer_by_File(args.tarSBOM)
                # return middle2
                middle1 = geekloud2cydx.transferFunc(args.tarSBOM)
                middle2 = geek_transfer.transfer(middle2)
                result = analysis_tools.analysis_by_Data_and_Data(middle2,middle1)
            else:
                logger.error(f"Geekloud's format is not legal for action {args.action}")
                return 
    if srcType == 'spdx' and tarType == 'cyclonedx':
        middle1 = spdx2geekloud.transferFunc(args.srcSBOM)
        middle1 = geek_transfer.transfer(middle1)
        result = analysis_tools.analysis_by_Data_and_File(middle1,args.tarSBOM)
    if srcType == 'cyclonedx' and tarType == 'spdx':
        middle1 = spdx2geekloud.transferFunc(args.tarSBOM)
        middle1 = geek_transfer.transfer(middle1)
        # return middle1
        result = analysis_tools.analysis_by_Data_and_File(middle1,args.srcSBOM)

    return result


    
################################

def transfer(args):
    if not is_Src_and_TarType_Valid(args):
        return
    if args.srcType == args.tarType:
        logger.error(f'source SBOM TYPE can not be the same as target SBOM TYPE for {args.action}')
        return 
    if not is_SrcSBOM_Valid(args):
        return 
    if args.srcType == 'geek' and utils.GeekLoud_format_By_File(args.srcSBOM) != utils.METADATA_DEPENDENCY_FORMAT:
        logger.error(f"Geekloud's format is not legal for action {args.action}")
        return 
    if not (args.srcType in ['cyclonedx','spdx'] and args.tarType in ['cyclonedx','spdx']):
        transferFunc = transferType(args)
        if transferFunc == None:
            logger.error(f"transferFunc is needed for action {args.action}")
            return
        data = transferFunc(args.srcSBOM)
        
        if args.tarType == 'geek' and args.verbose:
            return geek_transfer.transfer(data)
        else:
            return data
        # return data
    else: 
        if args.srcType == 'cyclonedx' and args.tarType == 'spdx':
            middle_geek = cydx2geekloud.transferFunc(args.srcSBOM)
            return geekloud2spdx.transferFunc_By_Data(middle_geek)
            # return middle_geek
            # return geekloud2spdx.transferFunc_By_Data(cydx2geekloud.transferFunc(args.srcSBOM))
        if args.srcType == 'spdx' and args.tarType == 'cyclonedx':
            middle_geek = spdx2geekloud.transferFunc(args.srcSBOM)
            # return middle_geek
            return geekloud2cydx.transferFunc_By_Data(middle_geek)
            # return geekloud2cydx.transferFunc_By_Data(spdx2geekloud.transferFunc(args.srcSBOM))
        # return data
    # with open(args.output,'w',encoding='UTF-8') as f:
    #     print(json.dumps(data, indent=4), file=f)
    

def transferType(args):
    srcType = args.srcType
    tarType = args.tarType
    transferFunc = None
    if srcType=='geek':
        if tarType=='cyclonedx':
            transferFunc = geekloud2cydx.transferFunc
        if tarType=='spdx':
            transferFunc = geekloud2spdx.transferFunc
    else :
        if srcType=='cyclonedx':
            if tarType=='geek':
                transferFunc = cydx2geekloud.transferFunc
        if srcType=='spdx':
            if tarType=='geek':
                transferFunc = spdx2geekloud.transferFunc
    return transferFunc

#################

action_dict = {
        dependency.__name__: dependency,
        transfer.__name__:transfer,
        compare.__name__:compare
        }

if __name__ == '__main__':
    args = parse_args()
    action = args.action
    
    if action not in action_dict:
        logger.error('Unknown action %s' % action)
        # exit(1)
    logger = logging.getLogger("error")
    logger.setLevel(level = logging.DEBUG)
    today = datetime.datetime.now()
    # log_path = "/root/osschain/logs/error-" + today.strftime("%Y-%m-%d-%H:%M:%S") + ".log"
    # log_path = "logs/error-" + today.strftime("%Y-%m-%d-%H:%M:%S") + ".log" 
    utils.mkdir(os.path.join(os.path.dirname(__file__),'logs'))
    log_path = "error-" + today.strftime("%Y-%m-%d-%H:%M:%S") + ".log" 
    log_path = os.path.join(os.path.dirname(__file__),'logs',log_path)
    print("log_path",log_path)
    rHandler = RotatingFileHandler(log_path)
    rHandler.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s')
    rHandler.setFormatter(formatter)
    logger.addHandler(rHandler)
    
    # if args.output == 'output.json':
    utils.mkdir(os.path.join(os.path.dirname(__file__),'output'))
    output_path = os.path.join(os.path.dirname(__file__),'output',args.output)
    print("output_path",output_path)
    try:
        data = action_dict[action](args)
        with open(output_path,'w',encoding='UTF-8') as f:
            print(json.dumps(data, indent=4), file=f)
            # json.dump(data,f)
    except:
        # logger.error("Faild To Dependency Analysis",exc_info = True)
        logger.error(f"Faild To {action} Analysis",exc_info = True)
    logger.info("Finish")
        # exit(0)

