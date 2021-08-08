@echo off

rem 判断go环境是否存在

if not exist %GOPATH% echo go env is not exist && goto end

rem 判断资源文件，不影响编译
if not exist ./conf.yaml echo 'conf.yaml' is not exist
if not exist ./lib echo 'lib' dir is not exist
if not exist ./offline_data mkdir offline_data && echo offline_data dir is create

echo Compiling............

rem go拉包
go mod tidy

rem 开始编译
if exist ./main.go go build -o run.exe

if exist ./run.exe (goto success) else (goto false)

:success
    echo Compilation is complete
    echo Please use the 'run.exe' file in the directory to run
    goto end

:false
    echo Compilation Error
    goto end

:end
    echo install program exit