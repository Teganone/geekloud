import json
import sys
import geek_transfer
import datetime


# def translate_components(cydxFile, component):
#     # print(component)
#     if len(component.split(":"))==4:
#         group, name, type, version = component.split(":")
#         tmp = {}
#         tmp["group"] = group
#         tmp["name"] = name
#         tmp["version"] = version
#         tmp["purl"] = "pkg:maven" + \
#             "/"+group+"/"+name+"@"+version+"?type="+type
#         tmp["type"] = type
#         tmp["bom-ref"] = "pkg:maven" + \
#             "/"+group+"/"+name+"@"+version+"?type="+type
#         cydxFile["components"].append(tmp)


def translate_components(cydxFile, node):
    # print(component)
    component = node
    component = component.split(":")
    tmp = {}
    if len(component) == 4:
        group, name, type, version = component
        tmp["group"] = group
        tmp["name"] = name
        tmp["version"] = version
        tmp["type"] = type
        tmp["purl"] = "pkg:maven" + \
            "/"+group+"/"+name+"@"+version+"?type="+type
        tmp["bom-ref"] = "pkg:maven" + \
            "/"+group+"/"+name+"@"+version+"?type="+type
    elif len(component) == 3:
        group, name, version = component
        type = "jar"
        tmp["group"] = group
        tmp["name"] = name
        tmp["version"] = version
        tmp["type"] = type
        tmp["purl"] = "pkg:maven" + \
            "/"+group+"/"+name+"@"+version+"?type="+type
        tmp["bom-ref"] = "pkg:maven" + \
            "/"+group+"/"+name+"@"+version+"?type="+type
    elif len(component) == 2:
        group, name = component
        type = "jar"
        tmp["group"] = group
        tmp["name"] = name
        tmp["type"] = "jar"
        tmp["purl"] = "pkg:maven" + \
            "/"+group+"/"+name+"@"+"?type="+type
        tmp["bom-ref"] = "pkg:maven" + \
            "/"+group+"/"+name+"@"+"?type="+type
    elif len(component) == 1:
        name = component[0]
        type = "jar"
        tmp["name"] = name
        tmp["type"] = "jar"
        tmp["purl"] = "pkg:maven" + "/"+name+"@"+"?type="+type
        tmp["bom-ref"] = "pkg:maven" + \
            "/"+name+"@"+"?type="+type
    cydxFile["components"].append(tmp)


# def translate_dependencies(cydxFile, component, links):
#     # print(len(component.split(":")))
#     if (len(component.split(":"))==4):
#         print(True)
#         group, name, type, version = component.split(":")
#         tmp = {}
#         component_modify = "pkg:maven" + \
#             "/"+group+"/"+name+"@"+version+"?type="+type
#         tmp["ref"] = component_modify
#         tmp["dependsOn"] = []
#         for node in links:
#             if node["source"] == component:
#                 group, name, type, version = node["target"].split(":")
#                 component_modify = "pkg:maven" + \
#                     "/"+group+"/"+name+"@"+version+"?type="+type
#                 tmp["dependsOn"].append(component_modify)
#         cydxFile["dependencies"].append(tmp)


def translate_dependencies(cydxFile, node, links):
    component = node
    source = node
    component = component.split(":")
    tmp = {}
    if (len(component) == 4):
        # print(True)
        group, name, type, version = component
        # tmp = {}
        component_modify = "pkg:maven" + \
            "/"+group+"/"+name+"@"+version+"?type="+type
    elif len(component) == 3:
        group, name, version = component
        component_modify = "pkg:maven" + \
            "/"+group+"/"+name+"@"+version+"?type="+"jar"
    elif len(component) == 2:
        group, name = component
        component_modify = "pkg:maven" + \
            "/"+group+"/"+name+"@"+"?type="+"jar"
    elif len(component) == 1:
        name = component[0]
        component_modify = "pkg:maven" + \
            "/"+name+"@"+"?type="+"jar"
    tmp["ref"] = component_modify
    tmp["dependsOn"] = []
    for node in links:
        if node["source"] == source:
            # print("source:"+source)
            # print("target:"+node["target"])

            if node["target"].count(":") == 0:
                component_modify = "pkg:maven" + \
                    "/"+node["target"]
            elif node["target"].count(":") == 1:
                group, name = node["target"].split(":")
                component_modify = "pkg:maven" + \
                    "/"+group+"/"+name+"@"+"?type="+"jar"
            elif node["target"].count(":") == 2:
                group, name, version = node["target"].split(":")
                component_modify = "pkg:maven" + \
                    "/"+group+"/"+name+"@"+version+"?type="+"jar"
            else:
                group, name, type, version = node["target"].split(":")
                component_modify = "pkg:maven" + \
                    "/"+group+"/"+name+"@"+version+"?type="+type
            # group, name, type, version = node["target"].split(":")
            # component_modify = "pkg:maven" + \
            #    "/"+group+"/"+name+"@"+version+"?type="+type
            tmp["dependsOn"].append(component_modify)
    cydxFile["dependencies"].append(tmp)


def transferFunc(src_SBOM_path, target_SBOM_path):
    # with open("/home/wxj/merge_pj/sca/osschain/dep-reports/kafka.json", 'r', encoding='UTF-8') as f:
    with open(src_SBOM_path, 'r', encoding='UTF-8') as f:
        geekloudFile = json.load(f)

    # 获取当前时间
    now = datetime.datetime.utcnow()

    # 格式化为指定格式字符串
    timestamp = now.strftime('%Y-%m-%dT%H:%M:%SZ')
    cydxFile = {"bomFormat": "CycloneDX",
                "specVersion": "1.4", "metadata": {"timestamp": timestamp, "tools": [{
                    "verdor": "GeekLoud", "name": "geek", "version": "1.0"}], "component": {}}, "components": [], "dependencies": []}
    component = next(iter(geekloudFile["dependency"]))  # 获取第一个键

    if component.count(":") == 1:
        group, name = component.split(":")
        cydxFile["metadata"]["component"]["group"] = group
        cydxFile["metadata"]["component"]["name"] = name
        cydxFile["metadata"]["component"]["purl"] = "pkg:maven" + \
            "/"+group+"/"+name+"@"+"?type="+"jar"
        cydxFile["metadata"]["component"]["bom-ref"] = "pkg:maven" + \
            "/"+group+"/"+name+"@"+"?type="+"jar"
    elif component.count(":") == 2:
        group, name, version = component.split(":")
        cydxFile["metadata"]["component"]["group"] = group
        cydxFile["metadata"]["component"]["name"] = name
        cydxFile["metadata"]["component"]["version"] = version
        cydxFile["metadata"]["component"]["purl"] = "pkg:maven" + \
            "/"+group+"/"+name+"@"+version+"?type="+"jar"
        cydxFile["metadata"]["component"]["bom-ref"] = "pkg:maven" + \
            "/"+group+"/"+name+"@"+version+"?type="+"jar"

    else:
        group, name, type, version = component.split(":")
        cydxFile["metadata"]["component"]["group"] = group
        cydxFile["metadata"]["component"]["name"] = name
        cydxFile["metadata"]["component"]["version"] = version
        cydxFile["metadata"]["component"]["purl"] = "pkg:maven" + \
            "/"+group+"/"+name+"@"+version+"?type="+type
        cydxFile["metadata"]["component"]["type"] = type
        cydxFile["metadata"]["component"]["bom-ref"] = "pkg:maven" + \
            "/"+group+"/"+name+"@"+version+"?type="+type

    # group, name, type, version = component.split(":")
    # cydxFile["metadata"]["component"]["group"] = group
    # cydxFile["metadata"]["component"]["name"] = name
    # cydxFile["metadata"]["component"]["version"] = version
    # cydxFile["metadata"]["component"]["purl"] = "pkg:maven" + \
    #    "/"+group+"/"+name+"@"+version+"?type="+type
    # cydxFile["metadata"]["component"]["type"] = type
    # cydxFile["metadata"]["component"]["bom-ref"] = "pkg:maven" + \
    #    "/"+group+"/"+name+"@"+version+"?type="+type

    geekloudFile = geek_transfer.transfer(geekloudFile)
    for node in geekloudFile["nodes"]:
        translate_components(cydxFile, node["name"])
        translate_dependencies(cydxFile, node["name"], geekloudFile["links"])

    # with open('./SBOM_analysis/SBOM/geek2cydx_dubbo.json','w',encoding='UTF-8') as f:
    with open(target_SBOM_path, 'w', encoding='UTF-8') as f:
        print(json.dumps(cydxFile, indent=4), file=f)
    # print(json.dumps(cydxFile, indent=4), file=sys.stdout)


def transferFunc(src_SBOM_path):
    # with open("/home/wxj/merge_pj/sca/osschain/dep-reports/kafka.json", 'r', encoding='UTF-8') as f:
    with open(src_SBOM_path, 'r', encoding='UTF-8') as f:
        geekloudFile = json.load(f)

    # 获取当前时间
    now = datetime.datetime.utcnow()

    # 格式化为指定格式字符串
    timestamp = now.strftime('%Y-%m-%dT%H:%M:%SZ')
    cydxFile = {"bomFormat": "CycloneDX",
                "specVersion": "1.4", "metadata": {"timestamp": timestamp, "tools": [{
                    "verdor": "GeekLoud", "name": "geek", "version": "1.0"}], "component": {}}, "components": [], "dependencies": []}
    component = next(iter(geekloudFile["dependency"]))  # 获取第一个键
    if component.count(":") == 1:
        group, name = component.split(":")
        cydxFile["metadata"]["component"]["group"] = group
        cydxFile["metadata"]["component"]["name"] = name
        cydxFile["metadata"]["component"]["purl"] = "pkg:maven" + \
            "/"+group+"/"+name+"@"+"?type="+"jar"
        cydxFile["metadata"]["component"]["bom-ref"] = "pkg:maven" + \
            "/"+group+"/"+name+"@"+"?type="+"jar"
    elif component.count(":") == 2:
        group, name, version = component.split(":")
        cydxFile["metadata"]["component"]["group"] = group
        cydxFile["metadata"]["component"]["name"] = name
        cydxFile["metadata"]["component"]["version"] = version
        cydxFile["metadata"]["component"]["purl"] = "pkg:maven" + \
            "/"+group+"/"+name+"@"+version+"?type="+"jar"
        cydxFile["metadata"]["component"]["bom-ref"] = "pkg:maven" + \
            "/"+group+"/"+name+"@"+version+"?type="+"jar"

    else:
        group, name, type, version = component.split(":")
        cydxFile["metadata"]["component"]["group"] = group
        cydxFile["metadata"]["component"]["name"] = name
        cydxFile["metadata"]["component"]["version"] = version
        cydxFile["metadata"]["component"]["purl"] = "pkg:maven" + \
            "/"+group+"/"+name+"@"+version+"?type="+type
        cydxFile["metadata"]["component"]["type"] = type
        cydxFile["metadata"]["component"]["bom-ref"] = "pkg:maven" + \
            "/"+group+"/"+name+"@"+version+"?type="+type

    # group, name, type, version = component.split(":")
    # cydxFile["metadata"]["component"]["group"] = group
    # cydxFile["metadata"]["component"]["name"] = name
    # cydxFile["metadata"]["component"]["version"] = version
    # cydxFile["metadata"]["component"]["purl"] = "pkg:maven" + \
    #    "/"+group+"/"+name+"@"+version+"?type="+type
    # cydxFile["metadata"]["component"]["type"] = type
    # cydxFile["metadata"]["component"]["bom-ref"] = "pkg:maven" + \
    #    "/"+group+"/"+name+"@"+version+"?type="+type

    geekloudFile = geek_transfer.transfer(geekloudFile)
    for node in geekloudFile["nodes"]:
        translate_components(cydxFile, node["name"])
        translate_dependencies(cydxFile, node["name"], geekloudFile["links"])

    return cydxFile


def transferFunc_By_Data(geekloudFile):
    # # with open("/home/wxj/merge_pj/sca/osschain/dep-reports/kafka.json", 'r', encoding='UTF-8') as f:
    # with open(src_SBOM_path, 'r', encoding='UTF-8') as f:
    #     geekloudFile = json.load(f)

    # 获取当前时间
    now = datetime.datetime.utcnow()

    # 格式化为指定格式字符串
    timestamp = now.strftime('%Y-%m-%dT%H:%M:%SZ')
    cydxFile = {"bomFormat": "CycloneDX",
                "specVersion": "1.4", "metadata": {"timestamp": timestamp, "tools": [{
                    "verdor": "GeekLoud", "name": "geek", "version": "1.0"}], "component": {}}, "components": [], "dependencies": []}
    component = next(iter(geekloudFile["dependency"]))  # 获取第一个键
    if component.count(":") == 1:
        group, name = component.split(":")
        cydxFile["metadata"]["component"]["group"] = group
        cydxFile["metadata"]["component"]["name"] = name
        cydxFile["metadata"]["component"]["purl"] = "pkg:maven" + \
            "/"+group+"/"+name+"@"+"?type="+"jar"
        cydxFile["metadata"]["component"]["bom-ref"] = "pkg:maven" + \
            "/"+group+"/"+name+"@"+"?type="+"jar"
    elif component.count(":") == 2:
        group, name, version = component.split(":")
        cydxFile["metadata"]["component"]["group"] = group
        cydxFile["metadata"]["component"]["name"] = name
        cydxFile["metadata"]["component"]["version"] = version
        cydxFile["metadata"]["component"]["purl"] = "pkg:maven" + \
            "/"+group+"/"+name+"@"+version+"?type="+"jar"
        cydxFile["metadata"]["component"]["bom-ref"] = "pkg:maven" + \
            "/"+group+"/"+name+"@"+version+"?type="+"jar"

    else:
        group, name, type, version = component.split(":")
        cydxFile["metadata"]["component"]["group"] = group
        cydxFile["metadata"]["component"]["name"] = name
        cydxFile["metadata"]["component"]["version"] = version
        cydxFile["metadata"]["component"]["purl"] = "pkg:maven" + \
            "/"+group+"/"+name+"@"+version+"?type="+type
        cydxFile["metadata"]["component"]["type"] = type
        cydxFile["metadata"]["component"]["bom-ref"] = "pkg:maven" + \
            "/"+group+"/"+name+"@"+version+"?type="+type
    # group, name, type, version = component.split(":")
    # cydxFile["metadata"]["component"]["group"] = group
    # cydxFile["metadata"]["component"]["name"] = name
    # cydxFile["metadata"]["component"]["version"] = version
    # cydxFile["metadata"]["component"]["purl"] = "pkg:maven" + \
    #    "/"+group+"/"+name+"@"+version+"?type="+type
    # cydxFile["metadata"]["component"]["type"] = type
    # cydxFile["metadata"]["component"]["bom-ref"] = "pkg:maven" + \
    #    "/"+group+"/"+name+"@"+version+"?type="+type

    geekloudFile = geek_transfer.transfer(geekloudFile)
    for node in geekloudFile["nodes"]:
        translate_components(cydxFile, node["name"])
        translate_dependencies(cydxFile, node["name"], geekloudFile["links"])

    return cydxFile
