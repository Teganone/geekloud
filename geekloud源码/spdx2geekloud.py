import json
import sys


def sbom_modify(s):
    if "/" not in s:
        return s
    if "@" not in s:
        # 使用replace方法将/替换为:
        name = s.replace("/", ":")
        # 使用rsplit方法去掉pom.xml
        name = name.rsplit(":", 1)[0]
        return name
    s = s[10:]
    index1 = s.find("/")
    index2 = s.find("@")
    # name = s[:index1]+":"+s[index1+1:index2]+":"+s[index2+1:]
    name = s[:index1]+":"+s[index1+1:index2]+":"+"jar"+":"+s[index2+1:]
    return name


def get_name(id, components):
    for i in components:
        for k, v in i.items():
            if id == k:
                return v


def push_child(children, dependencies, parent, depth):
    if (depth >= 3):
        return
    for i in dependencies:
        if i["ref"] == parent:
            if i["dependsOn"] == []:
                return
            for y in i["dependsOn"]:
                if (y != {}):
                    children[y] = {}
                    push_child(children[y], dependencies, y, depth+1)
            return


def transferFunc(src_SBOM_path,target_SBOM_path):
    # with open("/home/wxj/merge_pj/sca/SBOM_analysis/SBOM/dubbox.json", 'r', encoding='UTF-8') as f:
    with open(src_SBOM_path, 'r', encoding='UTF-8') as f:
        spdxFile = json.load(f)
    """ with open("/home/wxj/merge_pj/sca/text.json", 'r', encoding='UTF-8') as f:
        spdxFile = json.load(f) """

    geekloudFile = {"metadata": {}, "dependency": {}}
    geekloudFile["metadata"]["groupId"] = spdxFile["documentNamespace"].split(
        "/")[-1].split("-")[0]
    geekloudFile["metadata"]["version"] = "${revision}"
    geekloudFile["metadata"]["builder"] = "maven"
    components = []
    refs = set({})
    for package in spdxFile["packages"]:
        if "externalRefs" in package and package["externalRefs"]:
            referenceLocator = package["externalRefs"][0]["referenceLocator"]
            components.append({package["SPDXID"]: referenceLocator})
        elif "sourceInfo" in package and package["sourceInfo"]:
            sourceInfo = package["sourceInfo"]
            components.append({package["SPDXID"]: sourceInfo})
        else:
            name = package["name"]
            components.append({package["SPDXID"]: name})

    relationships = spdxFile["relationships"]
    dependencies = []
    for i in range(0, len(components)):
        for k, v in components[i].items():
            components[i][k] = sbom_modify(components[i][k])

    for i in range(0, len(relationships)):
        if relationships[i]["spdxElementId"] in refs:
            for j in dependencies:
                if j["ref"] == relationships[i]["spdxElementId"]:
                    j["dependsOn"].append(relationships[i]["relatedSpdxElement"])
                    break
        else:
            dependencies.append({"ref": relationships[i]["spdxElementId"], "dependsOn": [
                                relationships[i]["relatedSpdxElement"]]})
            refs.add(relationships[i]["spdxElementId"])

    for i in dependencies:
        i["ref"] = get_name(i["ref"], components)
        for j in range(0, len(i["dependsOn"])):
            i["dependsOn"][j] = get_name(i["dependsOn"][j], components)

    nodes = []
    for i in components:
        for v in i.values():
            nodes.append(v)

    for i in nodes:
        geekloudFile["dependency"][i] = {}
        push_child(geekloudFile["dependency"][i], dependencies, i, 1)

    # with open('./SBOM_analysis/SBOM/spdx2geek_dubbo.json','w',encoding='UTF-8') as f:
    with open(target_SBOM_path,'w',encoding='UTF-8') as f:
        # json.dumps(geekloudFile,indent=f)
        # print(json.dumps(geekloudFile, indent=4), file=sys.stdout)
        print(json.dumps(geekloudFile, indent=4), file=f)


def transferFunc(src_SBOM_path):
    # with open("/home/wxj/merge_pj/sca/SBOM_analysis/SBOM/dubbox.json", 'r', encoding='UTF-8') as f:
    with open(src_SBOM_path, 'r', encoding='UTF-8') as f:
        spdxFile = json.load(f)
    """ with open("/home/wxj/merge_pj/sca/text.json", 'r', encoding='UTF-8') as f:
        spdxFile = json.load(f) """

    geekloudFile = {"metadata": {}, "dependency": {}}
    geekloudFile["metadata"]["groupId"] = spdxFile["documentNamespace"].split(
        "/")[-1].split("-")[0]
    geekloudFile["metadata"]["version"] = "${revision}"
    geekloudFile["metadata"]["builder"] = "maven"
    components = []
    refs = set({})
    for package in spdxFile["packages"]:
        if "externalRefs" in package and package["externalRefs"]:
            referenceLocator = package["externalRefs"][0]["referenceLocator"]
            components.append({package["SPDXID"]: referenceLocator})
        elif "sourceInfo" in package and package["sourceInfo"]:
            sourceInfo = package["sourceInfo"]
            components.append({package["SPDXID"]: sourceInfo})
        else:
            name = package["name"]
            components.append({package["SPDXID"]: name})

    relationships = spdxFile["relationships"]
    dependencies = []
    for i in range(0, len(components)):
        for k, v in components[i].items():
            components[i][k] = sbom_modify(components[i][k])

    for i in range(0, len(relationships)):
        if relationships[i]["spdxElementId"] in refs:
            for j in dependencies:
                if j["ref"] == relationships[i]["spdxElementId"]:
                    j["dependsOn"].append(relationships[i]["relatedSpdxElement"])
                    break
        else:
            dependencies.append({"ref": relationships[i]["spdxElementId"], "dependsOn": [
                                relationships[i]["relatedSpdxElement"]]})
            refs.add(relationships[i]["spdxElementId"])

    for i in dependencies:
        i["ref"] = get_name(i["ref"], components)
        for j in range(0, len(i["dependsOn"])):
            i["dependsOn"][j] = get_name(i["dependsOn"][j], components)

    nodes = []
    for i in components:
        for v in i.values():
            nodes.append(v)

    for i in nodes:
        geekloudFile["dependency"][i] = {}
        push_child(geekloudFile["dependency"][i], dependencies, i, 1)
    return geekloudFile


def transferFunc_By_Data(spdxFile):
    # # with open("/home/wxj/merge_pj/sca/SBOM_analysis/SBOM/dubbox.json", 'r', encoding='UTF-8') as f:
    # with open(src_SBOM_path, 'r', encoding='UTF-8') as f:
    #     spdxFile = json.load(f)
    # """ with open("/home/wxj/merge_pj/sca/text.json", 'r', encoding='UTF-8') as f:
    #     spdxFile = json.load(f) """

    geekloudFile = {"metadata": {}, "dependency": {}}
    geekloudFile["metadata"]["groupId"] = spdxFile["documentNamespace"].split(
        "/")[-1].split("-")[0]
    geekloudFile["metadata"]["version"] = "${revision}"
    geekloudFile["metadata"]["builder"] = "maven"
    components = []
    refs = set({})
    for package in spdxFile["packages"]:
        if "externalRefs" in package and package["externalRefs"]:
            referenceLocator = package["externalRefs"][0]["referenceLocator"]
            components.append({package["SPDXID"]: referenceLocator})
        elif "sourceInfo" in package and package["sourceInfo"]:
            sourceInfo = package["sourceInfo"]
            components.append({package["SPDXID"]: sourceInfo})
        else:
            name = package["name"]
            components.append({package["SPDXID"]: name})

    relationships = spdxFile["relationships"]
    dependencies = []
    for i in range(0, len(components)):
        for k, v in components[i].items():
            components[i][k] = sbom_modify(components[i][k])

    for i in range(0, len(relationships)):
        if relationships[i]["spdxElementId"] in refs:
            for j in dependencies:
                if j["ref"] == relationships[i]["spdxElementId"]:
                    j["dependsOn"].append(relationships[i]["relatedSpdxElement"])
                    break
        else:
            dependencies.append({"ref": relationships[i]["spdxElementId"], "dependsOn": [
                                relationships[i]["relatedSpdxElement"]]})
            refs.add(relationships[i]["spdxElementId"])

    for i in dependencies:
        i["ref"] = get_name(i["ref"], components)
        for j in range(0, len(i["dependsOn"])):
            i["dependsOn"][j] = get_name(i["dependsOn"][j], components)

    nodes = []
    for i in components:
        for v in i.values():
            nodes.append(v)

    for i in nodes:
        geekloudFile["dependency"][i] = {}
        push_child(geekloudFile["dependency"][i], dependencies, i, 1)
    return geekloudFile
