import os
import sys
import json


def print_counts(dic):
    count = 0
    for k in dic.keys():
        count += len(dic[k])
    return count


def sbom_modify(s):
    s = s[10:]
    index1 = s.find("/")
    index2 = s.find("@")
    index3 = s.find("?")
    types = s[index3+1:]
    ls = types.split("=")
    ty = ""
    cla = ""
    if len(ls) == 2:
        ty = ls[1]
    else:
        cla = ls[1][:ls[1].find("&")]
        cla = ":"+cla
        ty = ls[2]

    name = s[:index1]+":"+s[index1+1:index2]+":"+ty+cla+":"+s[index2+1:index3]
    return name


    

def analysis(ours, sbom):
    result = {"total_counts":{},"components":{},"dependencies":{}}
    ls1 = sbom["components"]
    ls1 = [ls1[i]["bom-ref"] for i in range(0, len(ls1))]

    for i in range(0, len(ls1)):
        ls1[i] = sbom_modify(ls1[i])

    ls1.append(sbom_modify(sbom["metadata"]["component"]["bom-ref"]))

    ls2 = ours["nodes"]
    ls2 = [ls2[i]["name"] for i in range(0, len(ls2))]
    s1 = set(ls1)
    s2 = set(ls2)
    component_samelist = s1.intersection(s2)
    component_differentdict = {
        "SBOM": s1.difference(s2), "OURS": s2.difference(s1)}

    result["total_counts"]["component_samedict"] = len(component_samelist)
    result["total_counts"]["component_diffdict_osschain"] = len(component_differentdict["OURS"])
    result["total_counts"]["component_diffdict_comparedtools"] = len(component_differentdict["SBOM"])
    result["components"]["component_samedict"] = list(component_samelist)
    result["components"]["component_diffdict_osschain"] = list(component_differentdict["OURS"])
    result["components"]["component_diffdict_comparedtools"] = list(component_differentdict["SBOM"])

    ls1 = sbom["dependencies"]
    for i in range(0, len(ls1)):
        ls1[i]["ref"] = sbom_modify(ls1[i]["ref"])
        if ls1[i]["dependsOn"]:
            for j in range(0, len(ls1[i]["dependsOn"])):
                ls1[i]["dependsOn"][j] = sbom_modify(ls1[i]["dependsOn"][j])

    ls2 = ours["links"]
    dic2 = dict({})
    for i in range(0, len(ls2)):
        if ls2[i]["source"] in dic2.keys():
            dic2[ls2[i]["source"]].append(ls2[i]["target"])
        else:
            dic2[ls2[i]["source"]] = [ls2[i]["target"]]
    for k in dic2.keys():
        dic2[k] = list(set(dic2[k]))


    dic1 = dict({})
    for i in range(0, len(ls1)):
        if ls1[i]["dependsOn"]:
            dic1[ls1[i]["ref"]] = ls1[i]["dependsOn"]

    dependency_samedict = dict({})
    source_same_set = dic1.keys() & dic2.keys()
    dependency_differentdict = dict({"SBOM": {}, "OURS": {}})
    dependency_samesrc_difftag = dict({"SBOM": {}, "OURS": {}})
    sbom_diff = dic1.keys() - dic2.keys()
    ours_diff = dic2.keys() - dic1.keys()
    for i in source_same_set:
        dependency_samedict[i] = list(set(dic1[i]) & set(dic2[i]))

    for i in sbom_diff:
        dependency_differentdict["SBOM"][i] = dic1[i]

    for i in ours_diff:
        dependency_differentdict["OURS"][i] = dic2[i]

    for i in source_same_set:
        dependency_samesrc_difftag["SBOM"][i] = list(set(dic1[i]) - set(dic2[i]))
        dependency_samesrc_difftag["OURS"][i] = list(set(dic2[i]) - set(dic1[i]))

    result["total_counts"]["dependency_samesrc_sametag"] = print_counts(dependency_samedict)
    result["total_counts"]["dependency_samesrc_difftag_osschain"] = print_counts(dependency_samesrc_difftag["OURS"])
    result["total_counts"]["dependency_samesrc_difftag_comparedtools"] = print_counts(dependency_samesrc_difftag["SBOM"])
    result["total_counts"]["dependency_diffsrc_difftag_osschain"] = print_counts(dependency_differentdict["OURS"])
    result["total_counts"]["dependency_diffsrc_difftag_comparedtools"] = print_counts(dependency_differentdict["SBOM"])

    result["dependencies"]["dependency_samesrc_sametag"] =  dependency_samedict
    result["dependencies"]["dependency_samesrc_difftag_osschain"] = dependency_samesrc_difftag["OURS"]
    result["dependencies"]["dependency_samesrc_difftag_comparedtools"] = dependency_samesrc_difftag["SBOM"]
    result["dependencies"]["dependency_diffsrc_difftag_osschain"] = dependency_differentdict["OURS"]
    result["dependencies"]["dependency_diffsrc_difftag_comparedtools"] = dependency_differentdict["SBOM"]
    # print(json.dumps(result, indent=4), file=sys.stdout)
    return result



def analysis_by_File_and_File(osschain_output_file, comparedtools_output_file):
    with open(osschain_output_file, 'r', encoding='UTF-8') as f:
        ours = json.load(f)
    # print(ours)
    with open(comparedtools_output_file, 'r', encoding='UTF-8') as f:
        sbom = json.load(f)
    # print(sbom)
    return analysis(ours=ours,sbom=sbom)

def analysis_by_Data_and_Data(ours,sbom):
    return analysis(ours=ours,sbom=sbom)

def analysis_by_File_and_Data(file,data):
    with open(file,'r',encoding='UTF-8') as f:
        ours = json.load(f)
    return analysis(ours=ours,sbom=data)

def analysis_by_Data_and_File(data,file):
    with open(file,'r',encoding='UTF-8') as f:
        sbom = json.load(f)
    return analysis(ours=data,sbom=sbom)

