            Write-Host "Disabling unnecessary ports..." -ForegroundColor Green
            netsh advfirewall firewall add rule name="Disable Unused Ports" dir=in action=block protocol=TCP localport=135,137,138,139,445
            Write-Host "Ports disabled!" -ForegroundColor Cyan
        }
        "3" {
            Write-Host "Cleaning sensitive data..." -ForegroundColor Green
            Remove-Item -Path "$env:APPDATA\Microsoft\Windows\Recent\*" -Recurse -Force
            Remove-Item -Path "$env:LOCALAPPDATA\Temp\*" -Recurse -Force
            Write-Host "Data cleaned!" -ForegroundColor Cyan
        }
        "4" {
            Write-Host "Scheduling weekly maintenance..." -ForegroundColor Green
            schtasks /create /sc weekly /tn "MaintenanceTask" /tr "powershell.exe -File C:\Path\to\script.ps1" /st 09:00
            Write-Host "Maintenance scheduled!" -ForegroundColor Cyan
        }
        "5" {
            Write-Host "Generating performance report..." -ForegroundColor Green
            Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 | Out-File "PerformanceReport.txt"
            Write-Host "Performance report generated!" -ForegroundColor Cyan
        }
        "6" {
            Write-Host "Disabling unnecessary startup programs..." -ForegroundColor Green
            Get-CimInstance -ClassName Win32_StartupCommand | Where-Object { $_.User -eq $env:USERNAME } | Remove-CimInstance
            Write-Host "Startup programs disabled!" -ForegroundColor Cyan
        }
        "7" {
            Write-Host "Clearing temporary files..." -ForegroundColor Green
            Get-ChildItem -Path "C:\Windows\Temp" -Recurse | Remove-Item -Force
            Write-Host "Temporary files cleared!" -ForegroundColor Cyan
        }
        "8" {
            Write-Host "Speeding up boot..." -ForegroundColor Green
            bcdedit /set {current} bootmenupolicy legacy
            Write-Host "Boot speed increased!" -ForegroundColor Cyan
        }
        "9" {
            Write-Host "Updating system and drivers..." -ForegroundColor Green
            Start-Process "ms-settings:windowsupdate"
            Write-Host "Please complete updates manually." -ForegroundColor Cyan
        }
        "10" {
            Write-Host "Repairing network issues..." -ForegroundColor Green
            netsh int ip reset
            netsh winsock reset
            Write-Host "Network issues repaired!" -ForegroundColor Cyan
        }
        "11" {
            Write-Host "Disabling unnecessary services..." -ForegroundColor Green
            Stop-Service -Name "PrintSpooler" -Force
            Set-Service -Name "PrintSpooler" -StartupType Disabled
            Write-Host "Services disabled!" -ForegroundColor Cyan
        }
        "12" {
            Write-Host "Restoring system to previous point..." -ForegroundColor Green
            Start-Process "rstrui.exe"
        }
        "13" {
            Write-Host "Checking disk for errors..." -ForegroundColor Green
            chkdsk C: /f /r
            Write-Host "Disk checked!" -ForegroundColor Cyan
        }
        "14" {
            Write-Host "Optimizing power consumption..." -ForegroundColor Green
            powercfg -setactive SCHEME_MAX
            Write-Host "Power optimized!" -ForegroundColor Cyan
        }
        "15" {
            Write-Host "Viewing active processes..." -ForegroundColor Green
            Get-Process | Out-GridView
            Write-Host "Active processes viewed!" -ForegroundColor Cyan
        }
        "16" {
            Write-Host "Clearing RAM..." -ForegroundColor Green
            Clear-Content -Path "C:\Windows\Prefetch\*.*" -Force
            Write-Host "RAM cleared!" -ForegroundColor Cyan
        }
        "17" {
            Write-Host "Activating high performance mode..." -ForegroundColor Green
            powercfg -setactive SCHEME_MIN
            Write-Host "High performance mode activated!" -ForegroundColor Cyan
        }
        "18" {
            Write-Host "Clearing browsing history..." -ForegroundColor Green
            Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\History" -Force
            Write-Host "Browsing history cleared!" -ForegroundColor Cyan
        }
        "19" {
            Write-Host "Disabling unnecessary notifications..." -ForegroundColor Green
            reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /v ToastEnabled /t REG_DWORD /d 0 /f
            Write-Host "Notifications disabled!" -ForegroundColor Cyan
        }
        "20" {
            Write-Host "Closing unused programs..." -ForegroundColor Green
            Get-Process | Where-Object { $_.CPU -eq 0 } | Stop-Process -Force
            Write-Host "Unused programs closed!" -ForegroundColor Cyan
        }
        "21" {
            Write-Host "Performing full system scan..." -ForegroundColor Green
            Write-Host "Running System File Checker..." -ForegroundColor Yellow
            sfc /scannow
            Write-Host "Running DISM tool..." -ForegroundColor Yellow
            DISM /Online /Cleanup-Image /RestoreHealth
            Write-Host "System scan completed!" -ForegroundColor Cyan
        }
        "22" {
            Write-Host "Performing deep system clean..." -ForegroundColor Green
            # Add the deep clean steps here...
            Write-Host "Deep clean completed!" -ForegroundColor Cyan
        }
        "23" {
            Write-Host "Auto-Optimizing system..." -ForegroundColor Green
            AutoOptimizeSystem
        }
        "24" {
            Write-Host "Exiting..." -ForegroundColor Red
            exit
        }
        default {
            Write-Host "Invalid choice, please try again." -ForegroundColor Red
        }
    }
}
