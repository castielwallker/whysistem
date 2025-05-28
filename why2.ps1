
$ErrorActionPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# VARIÁVEIS PERSONALIZÁVEIS MAAD
$maadName = "Maad"
$maadGroup = "MaadGroup"
$maadComment = "Sistema personalizado por Maad"
$maadCPU = "Intel Quantum 9999X Turbo Maad Edition"
$maadBIOS = "MaadBIOS v9999"
$maadModel = "MaadX-2025 Ultimate"
$maadOwner = "Maad"
$maadOrg = "Maad Corporation"
$maadWallpaperURL = "https://i.imgur.com/BxYaE1e.jpeg"
$maadWallpaperPath = "$env:SystemRoot\Web\Wallpaper\Windows\maad_wallpaper.jpg"
$maadProgramName = "NVIDIA Shader Booster Pro"
$maadPublisher = "Maad Technologies"
$maadUninstallKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\MaadApp123"
$maadProductName = "Windows 10 Maad Edition"

function Show-MaadBanner {
    Write-Host @"


              ███╗   ███╗ █████╗  █████╗ ██████╗ 
              ████╗ ████║██╔══██╗██╔══██╗██╔══██╗
              ██╔████╔██║███████║███████║██║  ██║
              ██║╚██╔╝██║██╔══██║██╔══██║██║  ██║
              ██║ ╚═╝ ██║██║  ██║██║  ██║██████╔╝
              ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ 
  •  W H Y     N O T H I N G     F R E E     B Y P A S S     F R E E •	  
  ____________________________________________________________________
"@ -ForegroundColor White
}
function Set-MaadWallpaper {
    try {
        # Baixar wallpaper
        $client = New-Object System.Net.WebClient
        $client.DownloadFile($maadWallpaperURL, $maadWallpaperPath)
        
        # Definir como wallpaper
        Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "Wallpaper" -Value $maadWallpaperPath
        Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "WallpaperStyle" -Value "10"
        Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "TileWallpaper" -Value "0"
        rundll32.exe user32.dll,UpdatePerUserSystemParameters
    } catch {
        Write-Host "Erro ao configurar wallpaper: $_" -ForegroundColor Yellow
    }
}

function Apply-MaadCustomizations {
    # 1. NOME DO COMPUTADOR
    Rename-Computer -NewName $maadName -Force
    
    # 2. DESCRIÇÃO DO SERVIDOR
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "srvcomment" -Value $maadComment -Force
    
    # 3. FABRICANTE E MODELO
    (Get-WmiObject Win32_ComputerSystem).Manufacturer = $maadName
    (Get-WmiObject Win32_ComputerSystem).Model = $maadModel
    
    # 4. NOME DO PROCESSADOR
    Set-ItemProperty -Path "HKLM:\HARDWARE\DESCRIPTION\System\CentralProcessor\0" -Name "ProcessorNameString" -Value $maadCPU
    
    # 5. BIOS FAKE
    Set-ItemProperty -Path "HKLM:\HARDWARE\DESCRIPTION\System" -Name "SystemBiosVersion" -Value $maadBIOS -Force
    
    # 6. PROPRIETÁRIO DO WINDOWS
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    Set-ItemProperty -Path $regPath -Name "RegisteredOwner" -Value $maadOwner
    Set-ItemProperty -Path $regPath -Name "RegisteredOrganization" -Value $maadOrg
    Set-ItemProperty -Path $regPath -Name "ProductName" -Value $maadProductName
    
    # 7. PAPEL DE PAREDE MAAD
    Set-MaadWallpaper
    
    # 8. RENOMEAR USUÁRIO
    $CurrentUsername = $env:USERNAME
    Rename-LocalUser -Name $CurrentUsername -NewName $maadName
    
    # 9. ADICIONAR PROGRAMA FALSO NO REGISTRO
    New-Item -Path $maadUninstallKey -Force | Out-Null
    Set-ItemProperty -Path $maadUninstallKey -Name "DisplayName" -Value $maadProgramName
    Set-ItemProperty -Path $maadUninstallKey -Name "Publisher" -Value $maadPublisher
    Set-ItemProperty -Path $maadUninstallKey -Name "InstallDate" -Value (Get-Date -Format yyyyMMdd)
    Set-ItemProperty -Path $maadUninstallKey -Name "InstallLocation" -Value "C:\Program Files\$maadProgramName"
    Set-ItemProperty -Path $maadUninstallKey -Name "DisplayVersion" -Value "v9.9.9"
    Set-ItemProperty -Path $maadUninstallKey -Name "UninstallString" -Value "C:\MaadPath\uninstall.exe"
    
    # 10. FAKE NO LOG DE EVENTO (opcional)
    wevtutil im "$env:SystemRoot\System32\winevt\Logs\Application.evtx" > $null
    
    # 11. ALTERAR NOME DA PLACA DE REDE (onde possível)
    Get-NetAdapter | Where-Object { $_.InterfaceDescription -like "*Realtek*" } | Rename-NetAdapter -NewName "MaadNet"
    
    # 12. GRUPO DE TRABALHO
    if (-not (Get-WmiObject Win32_ComputerSystem).PartOfDomain) {
        Add-Computer -WorkgroupName $maadGroup -Force
    }
    
    # 13. Personalização adicional do sistema
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" -Name "Manufacturer" -Value $maadName
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" -Name "Model" -Value $maadModel
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" -Name "SupportHours" -Value "24/7 Maad Support"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" -Name "SupportPhone" -Value "+1 555-MAAD-SUPPORT"
}

function Show-Result {
    Write-Host "`n• Personalização Maad concluída com sucesso!" -ForegroundColor Green
    Write-Host "`n• Nome do Computador: $maadName"
    Write-Host "• Modelo: $maadModel"
    Write-Host "• Processador: $maadCPU"
    Write-Host "• BIOS: $maadBIOS"
    Write-Host "• Proprietário: $maadOwner"
    Write-Host "• Wallpaper: $maadWallpaperPath"
    Write-Host "`n• Algumas alterações podem requerer reinicialização para ter efeito completo." -ForegroundColor Yellow
}

# Verifica se está sendo executado como administrador
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Este script precisa ser executado como Administrador!" -ForegroundColor Red
    Start-Sleep -Seconds 3
    exit
}

# Execução principal
Clear-Host
Show-MaadBanner
Write-Host "`nEste script aplicará personalizações Maad no sistema." -ForegroundColor Yellow
Write-Host "Deseja continuar? (S/N)" -ForegroundColor Yellow
$confirmation = Read-Host

if ($confirmation -eq 'S' -or $confirmation -eq 's') {
    Apply-MaadCustomizations
    Show-Result
} else {
    Write-Host "Operação cancelada pelo usuário." -ForegroundColor Red
}

# Manter console aberto para visualização
Write-Host "`nPressione qualquer tecla para sair..."
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')