import json
import sys
import analysis_tools


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
    """ with open("/home/wxj/merge_pj/sca/SBOM_analysis/SBOM/bom.json", 'r', encoding='UTF-8') as f:
        cydxFile = json.load(f) """
    # with open("/home/wxj/merge_pj/sca/osschain/task/dubbo/target/bom.json", 'r', encoding='UTF-8') as f:
    with open(src_SBOM_path, 'r', encoding='UTF-8') as f:
        cydxFile = json.load(f)

    geekloudFile = {"metadata": {}, "dependency": {}}
    geekloudFile["metadata"]["groupId"] = cydxFile["metadata"]["component"]["group"]
    geekloudFile["metadata"]["version"] = cydxFile["metadata"]["component"]["version"]
    geekloudFile["metadata"]["builder"] = "maven"

    compnent = cydxFile["metadata"]["component"]["purl"]
    compnents = [compnent]
    compnents += [cydxFile["components"][i]["bom-ref"]
                for i in range(0, len(cydxFile["components"]))]

    for i in range(0, len(compnents)):
        compnents[i] = analysis_tools.sbom_modify(compnents[i])

    dependencies = cydxFile["dependencies"]
    for i in range(0, len(dependencies)):
        dependencies[i]["ref"] = analysis_tools.sbom_modify(dependencies[i]["ref"])
        if dependencies[i]["dependsOn"]:
            for j in range(0, len(dependencies[i]["dependsOn"])):
                dependencies[i]["dependsOn"][j] = analysis_tools.sbom_modify(
                    dependencies[i]["dependsOn"][j])
    for i in compnents:
        geekloudFile["dependency"][i] = {}
        push_child(geekloudFile["dependency"][i], dependencies, i, 1)


    """ print(json.dumps(dependencies, indent=4), file=sys.stdout) """

    # with open('./SBOM_analysis/SBOM/cydx2geek_dubbo.json','w',encoding='UTF-8') as f:
    with open(target_SBOM_path,'w',encoding='UTF-8') as f:
        print(json.dumps(geekloudFile, indent=4), file=f)
    # print(json.dumps(geekloudFile, indent=4), file=sys.stdout)


def transferFunc(src_SBOM_path):
    """ with open("/home/wxj/merge_pj/sca/SBOM_analysis/SBOM/bom.json", 'r', encoding='UTF-8') as f:
        cydxFile = json.load(f) """
    # with open("/home/wxj/merge_pj/sca/osschain/task/dubbo/target/bom.json", 'r', encoding='UTF-8') as f:
    with open(src_SBOM_path, 'r', encoding='UTF-8') as f:
        cydxFile = json.load(f)

    geekloudFile = {"metadata": {}, "dependency": {}}
    geekloudFile["metadata"]["groupId"] = cydxFile["metadata"]["component"]["group"]
    geekloudFile["metadata"]["version"] = cydxFile["metadata"]["component"]["version"]
    geekloudFile["metadata"]["builder"] = "maven"

    compnent = cydxFile["metadata"]["component"]["purl"]
    compnents = [compnent]
    compnents += [cydxFile["components"][i]["bom-ref"]
                for i in range(0, len(cydxFile["components"]))]

    for i in range(0, len(compnents)):
        compnents[i] = analysis_tools.sbom_modify(compnents[i])

    dependencies = cydxFile["dependencies"]
    for i in range(0, len(dependencies)):
        dependencies[i]["ref"] = analysis_tools.sbom_modify(dependencies[i]["ref"])
        if dependencies[i]["dependsOn"]:
            for j in range(0, len(dependencies[i]["dependsOn"])):
                dependencies[i]["dependsOn"][j] = analysis_tools.sbom_modify(
                    dependencies[i]["dependsOn"][j])
    for i in compnents:
        geekloudFile["dependency"][i] = {}
        push_child(geekloudFile["dependency"][i], dependencies, i, 1)


    return geekloudFile


def transferFunc_By_Data(cydxFile):
    # """ with open("/home/wxj/merge_pj/sca/SBOM_analysis/SBOM/bom.json", 'r', encoding='UTF-8') as f:
    #     cydxFile = json.load(f) """
    # # with open("/home/wxj/merge_pj/sca/osschain/task/dubbo/target/bom.json", 'r', encoding='UTF-8') as f:
    # with open(src_SBOM_path, 'r', encoding='UTF-8') as f:
    #     cydxFile = json.load(f)

    geekloudFile = {"metadata": {}, "dependency": {}}
    geekloudFile["metadata"]["groupId"] = cydxFile["metadata"]["component"]["group"]
    geekloudFile["metadata"]["version"] = cydxFile["metadata"]["component"]["version"]
    geekloudFile["metadata"]["builder"] = "maven"

    compnent = cydxFile["metadata"]["component"]["purl"]
    compnents = [compnent]
    compnents += [cydxFile["components"][i]["bom-ref"]
                for i in range(0, len(cydxFile["components"]))]

    for i in range(0, len(compnents)):
        compnents[i] = analysis_tools.sbom_modify(compnents[i])

    dependencies = cydxFile["dependencies"]
    for i in range(0, len(dependencies)):
        dependencies[i]["ref"] = analysis_tools.sbom_modify(dependencies[i]["ref"])
        if dependencies[i]["dependsOn"]:
            for j in range(0, len(dependencies[i]["dependsOn"])):
                dependencies[i]["dependsOn"][j] = analysis_tools.sbom_modify(
                    dependencies[i]["dependsOn"][j])
    for i in compnents:
        geekloudFile["dependency"][i] = {}
        push_child(geekloudFile["dependency"][i], dependencies, i, 1)


    return geekloudFile

