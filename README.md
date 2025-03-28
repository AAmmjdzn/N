<#
.SYNOPSIS
    NOVA - Advanced PC Optimization Tool (31 Commands)
#>

function Show-Menu {
    Clear-Host
    Write-Host ""
    Write-Host "NOVA / - Advanced PC Optimization (31 Commands)" -ForegroundColor Cyan
    Write-Host ""
    
    
    # تعريف جميع الأوامر مع تحديد طول ثابت لكل عمود
    $commands = @(
        @("1", "Optimize Performance",        "3", "Clean Sensitive Data"),
        @("2", "Dis UnnecessaryP",                 "4", "Power Plan"),
        @("5", "Disable Services",           "7", "Repair Windows"),
        @("6", "Unnecessary Starup",                  "8", "Speed Up Boot"),
        @("9", "Update System/D",                "10", "Repair Network Issues"),
        @("11", "Clean Temp Files",          "13", "Update Drivers"),
        @("12", "Optimize Startup",          "14", "Defragment Disk"),
        @("15", "View Processes",            "16", "Clear RAM"),
        @("17", "High Perf. Mode",           "18", "Clear History"),
        @("19", "DisableNotifications",     "20", "Close Programs"),
        @("21", "Full System Scan",          "22", "Deep Clean"),
        @("23", "Auto Optimize",             "24", "Clean Desk"),
        @("25", "Remove Duplicates",         "26", "Fix Audio"),
        @("27", "Reset DNS Cache",           "28", "Optimize Internet"),
        @("29", "Remove Bloatware",          "30", "Remove Edge"),
        @("31", "Remove OneDrive",           "32", "Restart PC")
    )


    # عرض الأوامر في جدول منظم
    foreach ($row in $commands) {
        $leftNum = $row[0].PadLeft(2)
        $leftText = $row[1].PadRight(20)
        $rightNum = $row[2].PadLeft(2)
        $rightText = $row[3].PadRight(20)
        
        $line = "[$($leftNum)] - $($leftText)  [$($rightNum)] - $($rightText)"
        $coloredLine = $line -replace '\[(\d+)\]', "[$([char]0x1b)[33m`$1$([char]0x1b)[37m]"
        Write-Host $coloredLine
    }
    
    Write-Host ""
    Write-Host "---"
    Write-Host -NoNewline "["
    Write-Host -NoNewline " 0" -ForegroundColor Yellow
    Write-Host "] - Exit" -ForegroundColor White
    Write-Host ""
}


function Invoke-Command {
    param($commandNumber)
    
    switch ($commandNumber) {
        0 { exit }
        
        1 { 
            Write-Host "Optimizing performance..." -ForegroundColor Green
            Stop-Service -Name "SysMain" -Force
            Set-Service -Name "SysMain" -StartupType Disabled
            Write-Host "Performance optimized!" -ForegroundColor Cyan
         }
        2 { 
            Write-Host "Disabling unnecessary ports..." -ForegroundColor Green
            netsh advfirewall firewall add rule name="Disable Unused Ports" dir=in action=block protocol=TCP localport=135,137,138,139,445
            Write-Host "Ports disabled!" -ForegroundColor Cyan
         }
        3 { 
            Write-Host "Cleaning sensitive data..." -ForegroundColor Green
            Remove-Item -Path "$env:APPDATA\Microsoft\Windows\Recent\*" -Recurse -Force
            Remove-Item -Path "$env:LOCALAPPDATA\Temp\*" -Recurse -Force
            Write-Host "Data cleaned!" -ForegroundColor Cyan
         }
        4 { 
            Write-Host "Scheduling weekly maintenance..." -ForegroundColor Green
            schtasks /create /sc weekly /tn "MaintenanceTask" /tr "powershell.exe -File C:\Path\to\script.ps1" /st 09:00
            Write-Host "Maintenance scheduled!" -ForegroundColor Cyan
         }
        5 { 
            Write-Host "Generating performance report..." -ForegroundColor Green
            Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 | Out-File "PerformanceReport.txt"
            Write-Host "Performance report generated!" -ForegroundColor Cyan
         }
        6 { 
            Write-Host "Disabling unnecessary startup programs..." -ForegroundColor Green
            Get-CimInstance -ClassName Win32_StartupCommand | Where-Object { $_.User -eq $env:USERNAME } | Remove-CimInstance
            Write-Host "Startup programs disabled!" -ForegroundColor Cyan
         }
        7 { 
            Write-Host "Clearing temporary files..." -ForegroundColor Green
            Get-ChildItem -Path "C:\Windows\Temp" -Recurse | Remove-Item -Force
            Write-Host "Temporary files cleared!" -ForegroundColor Cyan
         }
        8 { 
            Write-Host "Speeding up boot..." -ForegroundColor Green
            bcdedit /set {current} bootmenupolicy legacy
            Write-Host "Boot speed increased!" -ForegroundColor Cyan
         }
        9 { 
            Write-Host "Updating system and drivers..." -ForegroundColor Green
            Start-Process "ms-settings:windowsupdate"
            Write-Host "Please complete updates manually." -ForegroundColor Cyan
         }
        10 { 
            Write-Host "Repairing network issues..." -ForegroundColor Green
            netsh int ip reset
            netsh winsock reset
            Write-Host "Network issues repaired!" -ForegroundColor Cyan
         }
        11 { 
            Write-Host "Disabling unnecessary services..." -ForegroundColor Green
            Stop-Service -Name "PrintSpooler" -Force
            Set-Service -Name "PrintSpooler" -StartupType Disabled
            Write-Host "Services disabled!" -ForegroundColor Cyan
         }
        12 { 
            Write-Host "Restoring system to previous point..." -ForegroundColor Green
            Start-Process "rstrui.exe"
         }
        13 { 
            Write-Host "Checking disk for errors..." -ForegroundColor Green
            chkdsk C: /f /r
            Write-Host "Disk checked!" -ForegroundColor Cyan
         }
        14 { 
            Write-Host "Optimizing power consumption..." -ForegroundColor Green
            powercfg -setactive SCHEME_MAX
            Write-Host "Power optimized!" -ForegroundColor Cyan
         }
        15 {
            Write-Host "Viewing active processes..." -ForegroundColor Green
            Get-Process | Out-GridView
            Write-Host "Active processes viewed!" -ForegroundColor Cyan
        }
        16 { 
            Write-Host "Clearing RAM..." -ForegroundColor Green
            Clear-Content -Path "C:\Windows\Prefetch\*.*" -Force
            Write-Host "RAM cleared!" -ForegroundColor Cyan
         }
        17 { 
            Write-Host "Activating high performance mode..." -ForegroundColor Green
            powercfg -setactive SCHEME_MIN
            Write-Host "High performance mode activated!" -ForegroundColor Cyan
         }
        18 { 
            Write-Host "Clearing browsing history..." -ForegroundColor Green
            Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\History" -Force
            Write-Host "Browsing history cleared!" -ForegroundColor Cyan
         }
        19 { 
            Write-Host "Disabling unnecessary notifications..." -ForegroundColor Green
            reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /v ToastEnabled /t REG_DWORD /d 0 /f
            Write-Host "Notifications disabled!" -ForegroundColor Cyan
         }
        20 { 
            Write-Host "Closing unused programs..." -ForegroundColor Green
            Get-Process | Where-Object { $_.CPU -eq 0 } | Stop-Process -Force
            Write-Host "Unused programs closed!" -ForegroundColor Cyan
         }
        21 { 
            Write-Host "Performing full system scan..." -ForegroundColor Green
            Write-Host "Running System File Checker..." -ForegroundColor Yellow
            sfc /scannow
            Write-Host "Running DISM tool..." -ForegroundColor Yellow
            DISM /Online /Cleanup-Image /RestoreHealth
            Write-Host "System scan completed!" -ForegroundColor Cyan
         }
        22 { 
            Write-Host "Auto-Optimizing system..." -ForegroundColor Green
            AutoOptimizeSystem
         }
        23 { 
            Start-Process -FilePath "cleanmgr.exe"
         }
        24 { 
            Write-Host "Searching for duplicate files..." -ForegroundColor Green
            $files = Get-ChildItem -Path "C:\Users\$env:USERNAME\Documents" -Recurse | Group-Object Length | Where-Object { $_.Count -gt 1 }
            foreach ($group in $files) {
                $group.Group | Select-Object -Skip 1 | Remove-Item -Force
            }
            Write-Host "Duplicate files removed!" -ForegroundColor Cyan
         }
        25 { 
            Write-Host "Repairing sound issues..." -ForegroundColor Green
            Restart-Service -Name "Audiosrv" -Force
            Write-Host "Audio services restarted!" -ForegroundColor Cyan
         }
        26 { 
            Write-Host "Flushing DNS cache..." -ForegroundColor Green
            ipconfig /flushdns
            Write-Host "DNS cache cleared!" -ForegroundColor Cyan
         }
        27 { 
            Write-Host "Optimizing internet settings..." -ForegroundColor Green
            netsh int tcp set global autotuninglevel=high
            netsh int tcp set global rss=enabled
            Write-Host "Internet speed optimized!" -ForegroundColor Cyan
         }
        28 { 
            function Check-Admin {
                $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
                if (-not $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
                    Write-Host "Please run PowerShell as administrator!" -ForegroundColor Red
                    Exit
                }
            }
            
            function Remove-Bloatware {
                Write-Host "Removing bloatware..." -ForegroundColor Cyan
                $bloatware = @(
                    "Microsoft.3DBuilder", "Microsoft.BingFinance", "Microsoft.BingNews", 
                    "Microsoft.BingSports", "Microsoft.BingWeather", "Microsoft.GetHelp",
                    "Microsoft.Getstarted", "Microsoft.MicrosoftSolitaireCollection",
                    "Microsoft.MicrosoftStickyNotes", "Microsoft.Office.OneNote", 
                    "Microsoft.OneConnect", "Microsoft.People", "Microsoft.SkypeApp", 
                    "Microsoft.WindowsAlarms", "Microsoft.WindowsCamera", 
                    "Microsoft.WindowsMaps", "Microsoft.WindowsPhone", 
                    "Microsoft.WindowsSoundRecorder", "Microsoft.Xbox.TCUI",
                    "Microsoft.XboxGameOverlay", "Microsoft.XboxGamingOverlay",
                    "Microsoft.XboxIdentityProvider", "Microsoft.XboxSpeechToTextOverlay",
                    "Microsoft.YourPhone", "Microsoft.ZuneMusic", "Microsoft.ZuneVideo"
                )
            
                foreach ($app in $bloatware) {
                    Get-AppxPackage -Name $app | Remove-AppxPackage -ErrorAction SilentlyContinue
                }
                Write-Host "Bloatware removed successfully!" -ForegroundColor Green
            }
            
            function Optimize-Windows {
                Write-Host "Optimizing Windows performance..." -ForegroundColor Cyan
            
                Get-AppxPackage | Foreach { Disable-AppBackgroundTaskDiagnosticInfo -PackageFamilyName $_.PackageFamilyName -ErrorAction SilentlyContinue }
            
                reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsStore" /v AutoDownload /t REG_DWORD /d 2 /f
                reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v EnableTransparency /t REG_DWORD /d 0 /f
            
                Write-Host "Cleaning temporary files..." -ForegroundColor Yellow
                Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
                Remove-Item -Path "C:\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
                Write-Host "Temporary files removed!" -ForegroundColor Green
            
                Stop-Process -Name explorer -Force
                Start-Process explorer.exe
                Write-Host "Windows optimization completed!" -ForegroundColor Green
            }
            
            Check-Admin
            $answer = Read-Host "Enter Y to remove bloatware and optimize Windows performance"
            
            if ($answer -eq "Y") {
                Remove-Bloatware
                Optimize-Windows
            } else {
                Write-Host "No changes were made." -ForegroundColor Yellow
            }
            
        
         }
        29 { 
            function Remove-Edge {
                Write-Host "Removing Microsoft Edge..." -ForegroundColor Cyan
            
                $EdgePackage = Get-AppxPackage -AllUsers | Where-Object { $_.Name -like "Microsoft.MicrosoftEdge*" }
                if ($EdgePackage) {
                    Write-Host "Removing Edge AppxPackage..." -ForegroundColor Yellow
                    Get-AppxPackage -AllUsers -Name "Microsoft.MicrosoftEdge*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
                } else {
                    Write-Host "Edge AppxPackage not found or already removed." -ForegroundColor Green
                }
            
                $EdgeFolder = "C:\Program Files (x86)\Microsoft\Edge"
                if (Test-Path $EdgeFolder) {
                    Write-Host "Removing Edge program files..." -ForegroundColor Yellow
                    Remove-Item -Path $EdgeFolder -Recurse -Force -ErrorAction SilentlyContinue
                }
            
                $EdgeInstaller = "C:\Program Files (x86)\Microsoft\Edge\Application\setup.exe"
                if (Test-Path $EdgeInstaller) {
                    Write-Host "Running Edge uninstaller..." -ForegroundColor Yellow
                    Start-Process -FilePath $EdgeInstaller -ArgumentList "--uninstall --system-level --verbose-logging --force-uninstall" -NoNewWindow -Wait
                } else {
                    Write-Host "Edge uninstaller not found." -ForegroundColor Green
                }
            
                Write-Host "Microsoft Edge has been removed successfully!" -ForegroundColor Green
            }
            
            Remove-Edge
         }
        30 { 
            function Remove-OneDrive {
                Write-Host "Stopping OneDrive processes..." -ForegroundColor Cyan
                Stop-Process -Name "OneDrive" -Force -ErrorAction SilentlyContinue
            
                Write-Host "Uninstalling OneDrive..." -ForegroundColor Yellow
                $OneDrivePath = "$env:SystemRoot\SysWOW64\OneDriveSetup.exe"
                if (-not (Test-Path $OneDrivePath)) {
                    $OneDrivePath = "$env:SystemRoot\System32\OneDriveSetup.exe"
                }
                if (Test-Path $OneDrivePath) {
                    Start-Process -FilePath $OneDrivePath -ArgumentList "/uninstall" -NoNewWindow -Wait
                } else {
                    Write-Host "OneDrive uninstaller not found." -ForegroundColor Green
                }
            
                Write-Host "Removing OneDrive leftover files..." -ForegroundColor Yellow
                Remove-Item -Path "$env:USERPROFILE\OneDrive" -Recurse -Force -ErrorAction SilentlyContinue
                Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\OneDrive" -Recurse -Force -ErrorAction SilentlyContinue
                Remove-Item -Path "$env:PROGRAMDATA\Microsoft OneDrive" -Recurse -Force -ErrorAction SilentlyContinue
                Remove-Item -Path "$env:SYSTEMDRIVE\OneDriveTemp" -Recurse -Force -ErrorAction SilentlyContinue
            
                Write-Host "Removing OneDrive registry keys..." -ForegroundColor Yellow
                Remove-Item -Path "HKCU:\Software\Microsoft\OneDrive" -Recurse -Force -ErrorAction SilentlyContinue
                Remove-Item -Path "HKLM:\Software\Microsoft\OneDrive" -Recurse -Force -ErrorAction SilentlyContinue
            
                Write-Host "OneDrive has been successfully removed!" -ForegroundColor Green
            }
            
            Remove-OneDrive
         }
        31 { 
            $confirmation = Read-Host "Do you want to restart the PC? (Yes/No)"
            if ($confirmation -eq "Yes") {
                Restart-Computer -Force
             }
  
         }

         "32" {
            $confirmation = Read-Host "Do you want to restart the PC? (Yes/No)"
          if ($confirmation -eq "Yes") {
              Restart-Computer -Force
           }

        }

        
        default { Write-Host "Invalid command number" -ForegroundColor Red }
    }
    
    if ($commandNumber -ne 0) {
        Write-Host ""
        Write-Host "Operation completed. Press any key to continue..." -ForegroundColor Gray
        [Console]::ReadKey($true) | Out-Null
    }
}

# العرض الرئيسي
while ($true) {
    Show-Menu
    $choice = Read-Host "Select a command [0-32]"
    if ($choice -match '^\d+$') {
        Invoke-Command -commandNumber ([int]$choice)
    }
    else {
        Write-Host "Please enter a valid number" -ForegroundColor Red
        Start-Sleep -Seconds 2
    }
}
