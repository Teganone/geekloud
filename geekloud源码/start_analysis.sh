#!/bin/bash

path='./software_jsonfiles'
files=$(ls $path)
for file in $files
do
versions=$(cat $path/$file | jq '.version' | grep -o '".*"' | sed 's/"//g')
project=$(echo ${file%.*}| tr '[A-Z]' '[a-z]')
task_path=./task/$project/
    for version in $versions
        do
        cd $task_path
        if git checkout $version 
        then
                cd .. && cd ..
                if [ -f ./dep-reports/$project-$version.json ]  #注意括号前后一定要有空格
                then
                        echo "The file exist"
                else
                        echo $path:$project:$version >tmp.txt && python3 interface.py --action dependency --task ./$project > ./dep-reports/$project-$version.json || rm ./dep-reports/$project-$version.json 
                fi
        else
                cd .. && cd ..
                echo $project:$version >>failed_git.txt
        fi
        done
done