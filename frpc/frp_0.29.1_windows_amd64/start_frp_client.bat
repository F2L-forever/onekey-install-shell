@echo off
startlocal
color 0a
title ������͸������رմ˴��ڣ� by��ahl
Mode con cols=80 lines=30
:: ��ʼ��ȡ����ԱȨ��
 setlocal
 ::set uac=~uac_permission_tmp_%random%
 ::md "%SystemRoot%\system32\%uac%" 2>nul
 ::if %errorlevel%==0 ( rd "%SystemRoot%\system32\%uac%" >nul 2>nul ) else (
 ::   echo set uac = CreateObject^("Shell.Application"^)>"%temp%\%uac%.vbs"
   :: echo uac.ShellExecute "%~s0","","","runas",1 >>"%temp%\%uac%.vbs"
    ::echo WScript.Quit >>"%temp%\%uac%.vbs"
    ::"%temp%\%uac%.vbs" /f
    ::del /f /q "%temp%\%uac%.vbs" & exit )

:: ��ɻ�ȡ,������Կ�ʼд���Լ��Ĵ�����
cd /d %~dp0/bin

ECHO.
Echo  #############################################################################
ECHO. #
Echo  #  ������Ҫ����������ǰ׺��
ECHO. #
Echo  #  �硰aa�� �����������Ĵ�͸����Ϊ����aa.ngrok.qqmylove.top��
ECHO. #
Echo  #############################################################################
ECHO.

set /p clientid=  ����������ǰ׺��
echo.
set /p port=  ������˿ڣ�
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
echo #�޸Ĵ˴� >>%frpcFile%
echo user = %clientid%  >>%frpcFile%
echo login_fail_exit = true >>%frpcFile%
echo protocol = tcp >>%frpcFile%

echo [http] >>%frpcFile%
echo type = http >>%frpcFile%
echo local_ip = 127.0.0.1 >>%frpcFile%
echo #�޸Ĵ˴� >>%frpcFile%
echo local_port = %port% >>%frpcFile%
echo use_encryption = true >>%frpcFile%
echo use_compression = true >>%frpcFile%
echo #�޸Ĵ˴� >>%frpcFile%
echo subdomain =%clientid%  >>%frpcFile%

ECHO.��ʹ�� http://%clientid%.ngrok.qqmylove.top ������ķ���
echo.
ECHO.����رմ˴��ڣ�������ķ��񽫲�������������
frpc.exe -c %frpcFile%
