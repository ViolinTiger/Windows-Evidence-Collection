::2012/07/16 V1.0
::2012/10/01 V1.1 
::2012/10/03 V1.2
::2012/10/16 V1.3
::2012/10/29 V1.4
::2012/11/30 V1.4.2
::2012/12/10 V1.4.3
::2013/01/16 V1.4.4
::2013/04/25 V1.4.4-2
::2013/7/4 V1.4.4-3
::2013/7/4 V1.4.5  MBSA
::2013/9/10 V1.4.6  screensave ; accesscheck ; BrowserHistoryViewer
::2013/9/11 V1.4.6.1 mbsa problem ; reg HKCU
::2013/10/1 V1.4.6.2 rawcopy problem  ; usp problem
::2014/8/26 V1.4.6.4 ShimCacheParser ; net use Problem ; net share Problem
::2017/02/22 V1.4.7.1 add Raymond collect fuction .
::2020/12/09 V1.4.9

::ACSI Forensic info gather tool V.1.4.9
::Writed by ACSI TONY

@echo off

echo "    _____  _________   _________.___                "
echo "   /  _  \ \_   ___ \ /   _____/|   |               "
echo "  /  /_\  \/    \  \/ \_____  \ |   |               "
echo " /    |    \     \____/        \|   |               "
echo " \____|__  /\______  /_______  /|___|               "
echo "         \/        \/        \/                     "
echo "                                    AF V1.4.9       "

::Get OS version
::wmic os get Caption,CSDversion,OSArchitecture /value
::for /f "delims=" %%a in ('wmic os get Caption,CSDversion,OSArchitecture /value') do @echo %%a

for /f "delims=" %%a in ('wmic os get Caption') do if not %%a LSS "" set A_OS_Caption=%%a
for /f "delims=" %%a in ('wmic os get CSDversion') do if not %%a LSS "" set A_OS_CSDversion=%%a
for /f "delims=" %%a in ('wmic os get OSArchitecture') do if not %%a LSS "" set A_OS_OSArchitecture=%%a

@echo OS: %A_OS_Caption% 
@echo Version: %A_OS_CSDversion%
@echo Architecture: %A_OS_OSArchitecture%

::Get date of today
::set A_today=%date:~0,4%.%date:~5,2%.%date:~8,2%
set A_today=_


::Mkdir dir in current dir
echo. 
echo. 
echo ::Mkdir dir name: %~dp0\%A_today%_%USERDOMAIN%_%computername%
set A_forensic_data_dir=%~dp0\%A_today%_%USERDOMAIN%_%computername%
if not exist %A_forensic_data_dir%  mkdir %A_forensic_data_dir%

::Dump MFT
echo ::Dump MFT
if not exist %A_forensic_data_dir%\C_MFT  mkdir %A_forensic_data_dir%\C_MFT
if not exist %A_forensic_data_dir%\D_MFT  mkdir %A_forensic_data_dir%\D_MFT
%~dp0\rawcopy /FileNamePath:C:0 /OutputPath:%A_forensic_data_dir%\C_MFT\
%~dp0\rawcopy /FileNamePath:C:\$LogFile /OutputPath:%A_forensic_data_dir%\C_MFT\
%~dp0\rawcopy /FileNamePath:D:0 /OutputPath:%A_forensic_data_dir%\D_MFT\
%~dp0\rawcopy /FileNamePath:D:\$LogFile /OutputPath:%A_forensic_data_dir%\D_MFT\

::Analysis MFT
::echo.
echo :: Analysis MFT
%~dp0\analyzeMFT -f "%A_forensic_data_dir%\MFT\$MFT" -o %A_forensic_data_dir%\MFT\C_MFT.csv

::mkdir GP
if not exist %A_forensic_data_dir%\GP mkdir %A_forensic_data_dir%\GP
::auditpol 
auditpol /get /category:*  > %A_forensic_data_dir%\GP\auditpol.log


::tasks
if exist C:\windows\tasks\SCHEDLGU.txt  copy C:\windows\tasks\SCHEDLGU.txt  %A_forensic_data_dir%
if not exist  %A_forensic_data_dir%  mkdir  %A_forensic_data_dir%\tasks
xcopy C:\Windows\Tasks  %A_forensic_data_dir%\tasks /s /I /y /h
powershell -NonInteractive -Command "Get-ScheduledTask" > %A_forensic_data_dir%\tasks\PS_Task.log
powershell -NonInteractive -Command "Get-ScheduledTask | Get-ScheduledTaskInfo" > %A_forensic_data_dir%\tasks\PS_TaskInfo.log
powershell -NonInteractive -Command "Get-ScheduledTask | Export-ScheduledTask" > %A_forensic_data_dir%\tasks\PS_TaskExport.log



::Dump Windows event log
echo ::Dump Windows event log
if not exist %A_forensic_data_dir%\Evtx mkdir %A_forensic_data_dir%\Evtx
xcopy C:\Windows\System32\winevt %A_forensic_data_dir%\Evtx\  /H /E /J /Q


::Gather IP info
echo ::Gather IP info
set A_Info_filename=%A_forensic_data_dir%\info.txt
ipconfig > %A_Info_filename%
echo \n >> %A_Info_filename%
set >>  %A_Info_filename%
echo \n >> %A_Info_filename%
systeminfo >> %A_Info_filename%

::ipconfig /displaydns 
echo ::ipconfig /displaydns 
ipconfig /displaydns > %A_forensic_data_dir%\ipconfig.displaydns.log


::HotFix
powershell -NonInteractive -Command "Get-HotFix" >  %A_forensic_data_dir%\HotFix.log


::list user info
echo ::list user info
powershell -NonInteractive -Command "Get-LocalUser" >  %A_forensic_data_dir%\userinfo.log
powershell -NonInteractive -Command "Get-LocalGroup" >>  %A_forensic_data_dir%\userinfo.log
powershell -NonInteractive -Command "Get-LocalGroupMember Administrators" >>  %A_forensic_data_dir%\userinfo.log

::user sid 
::echo ::Get user sid info

wmic /output:"%A_forensic_data_dir%\wmic.useraccount.log" useraccount list Full 
wmic /output:"%A_forensic_data_dir%\wmic.group.log" group list Full

::Installed Program 
echo ::Get Installed Program
wmic /output:"%A_forensic_data_dir%\Installed_Program.log" product list full
powershell -NonInteractive -Command "Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate" >  %A_forensic_data_dir%\PS_Installed_Program.log

:: secedit
secedit /export /cfg %A_forensic_data_dir%\GP\%computername%.gp.ini /log %A_forensic_data_dir%\GP\%computername%.gp.log 
secedit /analyze /db  %A_forensic_data_dir%\GP\%computername%.gp.db  /cfg %A_forensic_data_dir%\GP\%computername%.gp.ini /log %A_forensic_data_dir%\GP\%computername%.gp.log 


:: run autoruns
echo ::run autoruns
::%~dp0\autorunsc.exe /accepteula -a -c -m -v  * > %A_forensic_data_dir%\autorun_verified.csv 
start /MIN /wait /B "" "%~dp0\autoruns.exe" /accepteula -a %A_forensic_data_dir%\%computername%_autorun_verified.arn

::Gather Volume C  file list
echo ::gather Volume C  file list ..
dir /a /s /tc /q C:\ >  %A_forensic_data_dir%\C_file_a.s.tc.q.log
dir /a /s /tc /q D:\ >  %A_forensic_data_dir%\D_file_a.s.tc.q.log
::dir /a /s /q  C:\  > %A_forensic_data_dir%\C_file.a.s.q.log

::run process explorer
echo ::run command line pocess explorer
%~dp0\listdlls /accepteula -v > %A_forensic_data_dir%\listdll.log 
%~dp0\pslist /accepteula -t > %A_forensic_data_dir%\pslist.log 
%~dp0\handle.exe /accepteula  -a > %A_forensic_data_dir%\handle.log

::Dump Hive
echo ::Dump Hive 
if not exist %A_forensic_data_dir%\Hive mkdir %A_forensic_data_dir%\Hive 
reg save HKLM\SYSTEM %A_forensic_data_dir%\Hive\system
reg save HKLM\SECURITY %A_forensic_data_dir%\Hive\security
reg save HKLM\SAM %A_forensic_data_dir%\Hive\sam
reg save HKLM\SOFTWARE %A_forensic_data_dir%\Hive\software
reg save HKCU %A_forensic_data_dir%\Hive\hkcu

::goto regripper


::Reg Ripper
:regripper




::DumpMemory




::prefetch
if not exist %A_forensic_data_dir%\Pefetch mkdir %A_forensic_data_dir%\Prefetch
xcopy C:\Windows\Prefetch  %A_forensic_data_dir%\Prefetch\ /H /E /J /Q



::arp table
echo ::dump arp
arp -a > %A_forensic_data_dir%\arp.txt
route print > %A_forensic_data_dir%%\RoutePrint.txt

::/etc/hosts
echo ::dump hosts
if not exist %A_forensic_data_dir%\HOSTS mkdir  %A_forensic_data_dir%\HOSTS
xcopy C:\windows\system32\drivers\etc\hosts %A_forensic_data_dir%\HOSTS\ /H /E /J /Q 

::usb
if not exist %A_forensic_data_dir%\USB mkdir %A_forensic_data_dir%\USB
if exist C:\windows\inf\setupapi.dev.log xcopy C:\windows\inf\setupapi.dev.log %A_forensic_data_dir%\USB\   
if exist C:\windows\setupapi.log xcopy C:\windows\inf\setupapi.log %A_forensic_data_dir%\USB\
if exist C:\windows\inf\setupapi.app.log xcopy C:\windows\inf\setupapi.app.log %A_forensic_data_dir%\USB\
if exist C:\windows\inf\setupapi.offline.log xcopy C:\windows\inf\setupapi.offline.log %A_forensic_data_dir%\USB\

%~dp0\usp -livesys -csv -separator "," > %A_forensic_data_dir%\USB\usb.log 


::BrowsingHistory 
if not exist %A_forensic_data_dir%\BrowserHV mkdir %A_forensic_data_dir%\BrowserHV
%~dp0\BrowsingHistoryView.exe /scomma %A_forensic_data_dir%\BrowserHV\browser_history.csv /SaveDirect  /HistorySource 1 /VisitTimeFilterType 1


::net use
echo. 
echo :Net use:
if not exist %A_forensic_data_dir%\Net mkdir %A_forensic_data_dir%\Net
net use /y >> %A_forensic_data_dir%\Net\net.use.log

::net share
echo. 
echo :Net share:
net share /y >> %A_forensic_data_dir%\Net\net.share.log

::net session
echo. 
echo :Net session:
net sessions /list >> %A_forensic_data_dir%\Net\net.session.log

::net account
echo. 
echo :Net Accounts:
net accounts >> %A_forensic_data_dir%\Net\net.account.log

::Interface
echo.
echo :GetInterface:
powershell -NonInteractive -Command "Get-NetAdapter | Out-File %A_forensic_data_dir%\Net\PS_Interface.log" 
echo.
echo :GetInterfaceIP:
powershell -NonInteractive -Command " Get-NetIPAddress| Out-File %A_forensic_data_dir%\Net\PS_InterfaceIP.log" 
echo.
echo :GetConnectionProfile:
powershell -NonInteractive -Command "Get-NetConnectionProfile | Out-File %A_forensic_data_dir%\Net\PS_ConnectionProfile.log" 
echo.
echo :GetConnection:
powershell -NonInter active -Command " Get-NetTCPConnection | Out-File %A_forensic_data_dir%\Net\PS_Connection.log" 




::service
%~dp0\psservice /accepteula query  > %A_forensic_data_dir%\%computername%_psservice.log
%~dp0\psservice /accepteula security > %A_forensic_data_dir%\%computername%_psservice.sec.log
powershell -NonInteractive -Command "Get-Service | Select-Object Name, DisplayName, Status, StartType" > %A_forensic_data_dir%\%computername%_PS_service.log
powershell -NonInteractive -Command "Get-CimInstance –ClassName Win32_Service | Select-Object Name, DisplayName,StartMode, State, PathName, StartName, ServiceType" > %A_forensic_data_dir%\%computername%_PS_service_detail.log

::ShimCacheParser
echo.
echo :ShimCacheParser
%~dp0\ShimCacheParser.exe -l > %A_forensic_data_dir%\ShimCacheParser.log

::AmcacheParser
echo.
echo :AmcacheParser
if not exist %A_forensic_data_dir%\Amcache mkdir %A_forensic_data_dir%\Amcache
%~dp0\RawCopy.exe /FileNamePath:%SystemRoot%\AppCompat\Programs\Amcache.hve /OutputPath:%A_forensic_data_dir%\Amcache
%~dp0\RawCopy.exe /FileNamePath:%SystemRoot%\AppCompat\Programs\Amcache.hve.LOG1 /OutputPath:%A_forensic_data_dir%\Amcache
%~dp0\RawCopy.exe /FileNamePath:%SystemRoot%\AppCompat\Programs\Amcache.hve.LOG2 /OutputPath:%A_forensic_data_dir%\Amcache



::scan virus --

::virus record

::screensave
echo ::screensave check
reg query "HKCU\Control Panel\Desktop" > %A_forensic_data_dir%\GP\reg_screenave.log

::Run subinacl
echo ::check privilege ...
%~dp0\subinacl /outputlog=%A_forensic_data_dir%/%computername%_service.log /testmode /service * /display
%~dp0\accesschk /accepteula -c * > %A_forensic_data_dir%/%computername%_acesschk_service.log



::run 7z
echo.
echo Packing...
%~dp0\7za a -r -pacerTGB! %A_forensic_data_dir%.7z %A_forensic_data_dir%
::7za t -pacerTGB! %A_forensic_data_dir%.7z

::remove dir

rmdir  /S /Q %A_forensic_data_dir%

::finish
echo.
echo ::Finish !!!

:finish
::clean set data
set A_today=
set A_forensic_data_dir=
set A_Info_filename=
set A_OS_Caption=
set A_OS_CSDversion=
set A_OS_OSArchitecture=
