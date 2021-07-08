#!/bin/bash

# 判断go环境是否存在

if [ ! -d $GOPATH ];then
 echo "go env is not exist"
fi

# 判断资源文件，不影响编译
if [ ! -f "./conf.yaml" ];then
  echo "'conf.yaml' is not exist"
fi
if [ ! -d "./offline_data" ];then
  mkdir offline_data && echo "offline_data dir is create"
fi
if [ ! -d "./lib" ];then
  echo "'./lib' is not exist"
fi

echo "Compiling............"

# go拉包
go mod tidy

# 开始编译

if [ -f "./main.go" ];then
  go build -o run
fi

if [ ! -f "./run" ];then
  echo "Compilation Error"
else
  echo "Compilation is complete"
  echo "Please use the run.exe file in the directory to run"
fi
echo "install program exit"
