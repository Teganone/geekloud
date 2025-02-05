import re
import os
import json
import csv
class statistic:
    def __init__(self) -> None:
        self.deps = set()
        self.software_list=['dubbo','elasticsearch','flink','flume','hive','kylin','opentsdb','pinpoint','presto','ranger','sentry','storm','tez','tomcat','zipkin','zookeeper']

    def parse(self,k: str):
        res = k.split(':')
        version = res[-1]
        name = res[-3]
        return name, version

    # 递归依赖分析函数
    def dependency_analyser(self,dep_json: dict):
        if dep_json == {}:
            return []
        else:
            for k, v in dep_json.items():
                dep, version = self.parse(k)
                self.deps.add(dep+'-'+version)
                self.dependency_analyser(v)


    def run(self):
        output = dict()
        result = dict()
        num = dict()
        self.deps = set()
        for software in self.software_list:
            self.deps = set()
            num[software] = 0
            for filename in os.listdir('./dep-reports'):
                if re.search(software,filename):
                    with open(os.path.join(os.getcwd()+'/dep-reports/',filename),'r') as f:
                        try:
                            json_item = json.load(f)
                        except:
                            os.remove(os.path.join(os.getcwd()+'/dep-reports/',filename))
                            continue
                        self.dependency_analyser(json_item['dependency'])
                    num[software]+=1
            result[software] = len(self.deps)
        print(result)
        print(num)

        output['status'] = 'True'
        output['analysis_num'] = num
        output['dep_num'] = result
        with open('./dependency_result.json','w',encoding= 'utf-8') as file:
            json.dump(output,file, indent=4,ensure_ascii=False)
         

if __name__ == '__main__':
    statistic().run()
            # result.append([filename,length])
    # with open('./result.csv','w',newline='') as file:
    #         writer = csv.writer(file)
    #         writer.writerows(result)
    # for filename in os.listdir('./dep-reports'):
    #     with open(os.path.join(os.getcwd()+'/dep-reports/',filename),'r') as f:
    #         try:
    #             json_item = json.load(f)
    #             dependency_analyser(json_item)
    #             continue
        

