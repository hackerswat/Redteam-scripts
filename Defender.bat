@echo off
:: Prompt for UAC elevation
echo Requesting elevation...
echo.
echo $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
echo $  Please disable Tamper protection  $
echo $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
echo.
if not "%1"=="am_admin" (powershell start -verb runas '%0' am_admin & exit /b)

:start
cls
echo ===========================
echo Choose an option:
echo 1. Disable Windows Defender
echo 2. Enable Windows Defender
echo 3. Disable sample submission
echo 4. Enable sample submission
echo ===========================
set /p option="Enter option number (1-4): "

if "%option%"=="1" (
    echo Disabling Windows Defender...
    
    Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScanOnRealtimeEnable" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "ScanWithAntiVirus" /t REG_DWORD /d "1" /f

    echo Windows Defender has been disabled.
    echo Your settings have changed. Please reboot your computer for these changes to take effect!
    pause
    exit
)

if "%option%"=="2" (
    echo Enabling Windows Defender...
    
    Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScanOnRealtimeEnable" /t REG_DWORD /d "0" /f
    Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /f
    Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "ScanWithAntiVirus" /t REG_DWORD /d "3" /f

    echo Windows Defender has been enabled.
    echo Your settings have changed. Please reboot your computer for these changes to take effect!
    pause
    exit
)

if "%option%"=="3" (
    echo Disabling sample submission...
    
    Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d "2" /f

    echo Sample submission has been disabled.
    echo Your settings have changed. Please reboot your computer for these changes to take effect!
    pause
    exit
)

if "%option%"=="4" (
    echo Enabling sample submission...
    
    echo yes | Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent"
    
    echo Sample submission has been enabled.
    echo Your settings have changed. Please reboot your computer for these changes to take effect!
    pause
    exit
)

echo Invalid option selected. Please try again.
pause
goto start
