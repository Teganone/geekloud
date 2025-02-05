import json

# 转换依赖关系为字典
nodes = []
nodes_res = []
links = []
seen_links = set()  # 存储已经处理过的链接


def modify_nodes(module_key):
    pure_name = module_key.split(":")
    group_id = ""
    artifact = ""
    artifact_type = ""
    aop_flag = ""
    version = ""
    scope = ""
    if len(pure_name) == 6:
        group_id, artifact, artifact_type, aop_flag, version, scope = pure_name
        version = version + '-' + aop_flag
    elif len(pure_name) == 5:
        group_id, artifact, artifact_type, version, scope = pure_name
    # else:
    #     group_id, artifact, artifact_type, version = pure_name
    elif len(pure_name) == 4:
        group_id, artifact, artifact_type, version = pure_name
    elif len(pure_name) == 3:
        group_id, artifact, version = pure_name
    elif len(pure_name) == 2:   
        group_id, artifact = pure_name
    else:
        artifact = pure_name
    cnt = pure_name[0].count(".")
    if cnt == 0:
        make_type = pure_name[0]
    elif cnt == 1:
        make_type = pure_name[0][pure_name[0].index(".")+1:]
    else:
        make_type = pure_name[0][pure_name[0].index(".")+1:]
        make_type = make_type[:make_type.index(".")]

    if "strictly" in version:
        if(len(version.split(" "))==1 or len(version.split(" ")==0)):
            version = ''
        else:
            version = version.split(" ")[1]
            if '[' in version:
                version = version[1:len(version)-1]
            if len(pure_name) == 6:
                pure_name[4] = version
            else:
                pure_name[3] = version
    nodes_res.append({"name": ":".join(
        pure_name), "shortname": artifact, "type": artifact_type, "version": version, "maketype": make_type})

def modify_keys(pure_name):
    # print(pure_name)
    pure_name = pure_name.split(":")
    group_id = ""
    artifact = ""
    artifact_type = ""
    aop_flag = ""
    version = ""
    scope = ""
    if len(pure_name) == 6:
        group_id, artifact, artifact_type, aop_flag, version, scope = pure_name
        version = version + '-' + aop_flag
    elif len(pure_name) == 5:
        group_id, artifact, artifact_type, version, scope = pure_name
    elif len(pure_name) == 4:
        group_id, artifact, artifact_type, version = pure_name
    elif len(pure_name) == 3:
        group_id, artifact, version = pure_name
    elif len(pure_name) == 2:   
        group_id, artifact = pure_name
    else:
        artifact = pure_name
    if "strictly" in version:   
        # print(version)
        if(len(version.split(" "))==1 or len(version.split(" ")==0)):
            version = ''
        else:
            version = version.split(" ")[1]
            if '[' in version:
                version = version[1:len(version)-1]
            if len(pure_name) == 6:
                pure_name[4] = version
            else:
                pure_name[3] = version
    return ":".join(pure_name)
def process_dependency(dependency):
    for key, value in dependency.items():
        key = modify_keys(key)
        if key not in nodes:
            nodes.append(key)
        if isinstance(value, dict):
            for k, v in value.items():
                if k not in nodes:
                    k = modify_keys(k)
                    nodes.append(k)
                link = {'source': key, 'target': k}
                # 将链接转换为元组，然后检查是否在集合中出现过
                link_tuple = tuple(sorted(link.items()))
                if link_tuple in seen_links:
                    continue
                # 否则将链接加入到集合和links列表中
                seen_links.add(link_tuple)
                links.append(link)
                process_dependency({k: v})


# 测试代码
def transfer(data):
    process_dependency(data['dependency'])
    for i in nodes:
        modify_nodes(i)
    result = {'nodes': nodes_res, 'links': links}
    return result


# 测试代码
def transfer_by_File(data_file):
    with open(data_file,'r',encoding='UTF-8') as f:
        data = json.load(f)
    process_dependency(data['dependency'])
    for i in nodes:
        modify_nodes(i)
    result = {'nodes': nodes_res, 'links': links}
    return result
