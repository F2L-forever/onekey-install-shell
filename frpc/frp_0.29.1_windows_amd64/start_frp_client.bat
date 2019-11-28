@echo off
startlocal
color 0a
title 内网穿透（请勿关闭此窗口） by：ahl
Mode con cols=80 lines=30
:: 开始获取管理员权限
 setlocal
 ::set uac=~uac_permission_tmp_%random%
 ::md "%SystemRoot%\system32\%uac%" 2>nul
 ::if %errorlevel%==0 ( rd "%SystemRoot%\system32\%uac%" >nul 2>nul ) else (
 ::   echo set uac = CreateObject^("Shell.Application"^)>"%temp%\%uac%.vbs"
   :: echo uac.ShellExecute "%~s0","","","runas",1 >>"%temp%\%uac%.vbs"
    ::echo WScript.Quit >>"%temp%\%uac%.vbs"
    ::"%temp%\%uac%.vbs" /f
    ::del /f /q "%temp%\%uac%.vbs" & exit )

:: 完成获取,下面可以开始写你自己的代码了
cd /d %~dp0/bin

ECHO.
Echo  #############################################################################
ECHO. #
Echo  #  输入需要启动的域名前缀，
ECHO. #
Echo  #  如“aa” ，即分配给你的穿透域名为：“aa.ngrok.qqmylove.top”
ECHO. #
Echo  #############################################################################
ECHO.

set /p clientid=  请输入域名前缀：
echo.
set /p port=  请输入端口：
set frpcFile="frpc.ini"
::if exist "%~dp0\%frpcFile%" del /f /q "%~dp0\%frpcFile%"
echo [common] >%frpcFile%
echo server_addr = 120.25.225.59 >>%frpcFile%
echo server_port = 7000 >>%frpcFile%
echo log_file = $logfile >>%frpcFile%
echo log_level = info >>%frpcFile%
echo log_max_days = 3 >>%frpcFile%
echo token = ZpZy8AAS6EkuGsfz >>%frpcFile%
echo pool_count = 50 >>%frpcFile%
echo tcp_mux = true >>%frpcFile%
echo #修改此处 >>%frpcFile%
echo user = %clientid%  >>%frpcFile%
echo login_fail_exit = true >>%frpcFile%
echo protocol = tcp >>%frpcFile%

echo [http] >>%frpcFile%
echo type = http >>%frpcFile%
echo local_ip = 127.0.0.1 >>%frpcFile%
echo #修改此处 >>%frpcFile%
echo local_port = %port% >>%frpcFile%
echo use_encryption = true >>%frpcFile%
echo use_compression = true >>%frpcFile%
echo #修改此处 >>%frpcFile%
echo subdomain =%clientid%  >>%frpcFile%

ECHO.请使用 http://%clientid%.ngrok.qqmylove.top 访问你的服务
echo.
ECHO.请勿关闭此窗口，否则你的服务将不能在外网访问
frpc.exe -c %frpcFile%
