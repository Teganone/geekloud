import json
from pickle import FALSE
import sys
import geek_transfer
import datetime
import argparse


def translate_components(spdxFile, component, id):
    # print(component)
    if component.count(":") == 4:
        group, name, type, useless, version = component.split(":")
    else:
        group, name, type, version = component.split(":")
    tmp = {}
    tmp["group"] = group
    tmp["name"] = name
    tmp["version"] = version
    tmp["purl"] = "pkg:maven" + \
        "/"+group+"/"+name+"@"+version
    package = {"name": group+"." + name, "SPDXID": "SPDXRef-Application-"+str(id),
               "downloadLocation": "NOASSERTION",
               "filesAnalyzed": False,
               "licenseConcluded": "NOASSERTION",
               "licenseDeclared": "NOASSERTION",
               "copyrightText": "NOASSERTION",
               "versionInfo": version,
               "externalRefs": [
                   {
                       "referenceCategory": "PACKAGE-MANAGER",
                       "referenceType": "purl",
                       "referenceLocator": tmp["purl"],
                   }
    ],
        "supplier": "NOASSERTION"
    }
    spdxFile["packages"].append(package)


def translate_dependencies(spdxFile, link):
    if link["source"].count(":") == 4:
        group, name, type, useless, version = link["source"].split(":")
    else:
        group, name, type, version = link["source"].split(":")
    source = {}
    source["purl"] = "pkg:maven" + \
        "/"+group+"/"+name+"@"+version
    if link["target"].count(":") == 4:
        group, name, type, useless, version = link["target"].split(":")
    else:
        group, name, type, version = link["target"].split(":")
    target = {}
    target["purl"] = "pkg:maven" + \
        "/"+group+"/"+name+"@"+version
    relationship = {"relationshipType": "DEPENDS_ON"}
    for node in spdxFile["packages"]:
        if node["externalRefs"][0]["referenceLocator"] == source["purl"]:
            relationship["spdxElementId"] = node["SPDXID"]

    for node in spdxFile["packages"]:
        if node["externalRefs"][0]["referenceLocator"] == target["purl"]:
            relationship["relatedSpdxElement"] = node["SPDXID"]
    spdxFile["relationships"].append(relationship)


# def parse_args():
#     parser = argparse.ArgumentParser()
#     parser.add_argument('--src',default="/home/wxj/merge_pj/sca/osschain/dep-reports/dubbo-2.7.5.json",help='the src file')
#     parser.add_argument('--target',default='./target.json',help='the destination file')
#     args = parser.parse_args()
#     return args


def transferFunc(src_SBOM_path, target_SBOM_path):
    with open(src_SBOM_path, 'r', encoding='UTF-8') as f:
        geekloudFile = json.load(f)
    # 获取当前时间
    now = datetime.datetime.utcnow()

    # 格式化为指定格式字符串
    timestamp = now.strftime('%Y-%m-%dT%H:%M:%SZ')
    spdxFile = {"spdxVersion": "SPDX-2.2", "dataLicense": "CC0-1.0",
                "SPDXID": "SPDXRef-DOCUMENT", "name": geekloudFile["metadata"]["groupId"].split(".")[-1],
                "documentNamespace": "Geekloud", "CreationInfo": {"created": timestamp, "Creators": ["Tool: Geekloud"]},
                "packages": [], "relationships": []}

    geekloudFile = geek_transfer.transfer(geekloudFile)
    id = 1
    for node in geekloudFile["nodes"]:
        translate_components(spdxFile, node["name"], id)
        id += 1
    for link in geekloudFile["links"]:
        translate_dependencies(spdxFile, link)
    # with open('./SBOM_analysis/SBOM/geek2spdx_dubbo.json','w',encoding='UTF-8') as f:
    with open(target_SBOM_path, 'w', encoding='UTF-8') as f:
        print(json.dumps(spdxFile, indent=4), file=f)
    # print(json.dumps(spdxFile, indent=4), file=sys.stdout)


def transferFunc(src_SBOM_path):
    with open(src_SBOM_path, 'r', encoding='UTF-8') as f:
        geekloudFile = json.load(f)
    # 获取当前时间
    now = datetime.datetime.utcnow()

    # 格式化为指定格式字符串
    timestamp = now.strftime('%Y-%m-%dT%H:%M:%SZ')
    spdxFile = {"spdxVersion": "SPDX-2.2", "dataLicense": "CC0-1.0",
                "SPDXID": "SPDXRef-DOCUMENT", "name": geekloudFile["metadata"]["groupId"].split(".")[-1],
                "documentNamespace": "Geekloud", "CreationInfo": {"created": timestamp, "Creators": ["Tool: Geekloud"]},
                "packages": [], "relationships": []}

    geekloudFile = geek_transfer.transfer(geekloudFile)
    id = 1
    for node in geekloudFile["nodes"]:
        translate_components(spdxFile, node["name"], id)
        id += 1
    for link in geekloudFile["links"]:
        translate_dependencies(spdxFile, link)
    return spdxFile


def transferFunc_By_Data(geekloudFile):
    # with open(src_SBOM_path, 'r', encoding='UTF-8') as f:
    #     geekloudFile = json.load(f)
    # 获取当前时间
    now = datetime.datetime.utcnow()

    # 格式化为指定格式字符串
    timestamp = now.strftime('%Y-%m-%dT%H:%M:%SZ')
    spdxFile = {"spdxVersion": "SPDX-2.2", "dataLicense": "CC0-1.0",
                "SPDXID": "SPDXRef-DOCUMENT", "name": geekloudFile["metadata"]["groupId"].split(".")[-1],
                "documentNamespace": "Geekloud", "CreationInfo": {"created": timestamp, "Creators": ["Tool: Geekloud"]},
                "packages": [], "relationships": []}

    geekloudFile = geek_transfer.transfer(geekloudFile)
    id = 1
    for node in geekloudFile["nodes"]:
        translate_components(spdxFile, node["name"], id)
        id += 1
    for link in geekloudFile["links"]:
        translate_dependencies(spdxFile, link)
    return spdxFile


# if __name__ == '__main__':
#     args = parse_args()
#     src_SBOM_path  = args.src
#     target_SBOM_path = args.target

#     with open(src_SBOM_path, 'r', encoding='UTF-8') as f:
#         geekloudFile = json.load(f)
#     # 获取当前时间
#     now = datetime.datetime.utcnow()

#     # 格式化为指定格式字符串
#     timestamp = now.strftime('%Y-%m-%dT%H:%M:%SZ')
#     spdxFile = {"spdxVersion": "SPDX-2.2", "dataLicense": "CC0-1.0",
#                 "SPDXID": "SPDXRef-DOCUMENT", "name": geekloudFile["metadata"]["groupId"].split(".")[-1],
#                 "documentNamespace": "Geekloud", "CreationInfo": {"created": timestamp, "Creators": ["Tool: Geekloud"]},
#                 "packages": [], "relationships": []}

#     geekloudFile = transfer.transfer(geekloudFile)
#     id = 1
#     for node in geekloudFile["nodes"]:
#         translate_components(spdxFile, node["name"], id)
#         id += 1
#     for link in geekloudFile["links"]:
#         translate_dependencies(spdxFile, link)
#     # with open('./SBOM_analysis/SBOM/geek2spdx_dubbo.json','w',encoding='UTF-8') as f:
#     with open(target_SBOM_path,'w',encoding='UTF-8') as f:
#         print(json.dumps(spdxFile, indent=4), file=f)
#     # print(json.dumps(spdxFile, indent=4), file=sys.stdout)
