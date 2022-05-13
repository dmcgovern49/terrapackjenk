Function DisableWindowsErrReport()
{
    Set-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name Disabled -value 1 -type DWord -Force
}  

Function SetVisualAffectReg()
{
    Set-ItemProperty -path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name VisualFXSetting -value 2 -type DWord -Force
}

Function SetStandardReg()
{
    Set-ItemProperty -path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters -Name MaxTokenSize -value 48000 -type DWord -Force
    #Disabling RC4 Cipher through Registry
    $RC4RegPath = "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers"
    @('RC4 40/128','RC4 56/128','RC4 128/128') | %{$key = (Get-Item HKLM:\).OpenSubKey($RC4RegPath, $true).CreateSubKey($_);$key.SetValue('Enabled', 0, 'DWord');$key.close()}
    # Setting Security Settings
    new-item -Name Explorer -path "HKLM:\Software\Policies\Microsoft\Windows" -type Directory -Force
    set-itemproperty "HKLM:\Software\Policies\Microsoft\Windows\Explorer" -Name NoAutoplayfornonVolume -type DWord -Value 0x00000001 -Force
    new-item -Name Personalization -path "HKLM:\Software\Policies\Microsoft\Windows" -type Directory -Force
    set-itemproperty "HKLM:\Software\Policies\Microsoft\Windows\Personalization" -Name NoLockScreenCamera -type DWord -Value 0x00000001 -Force
    set-itemproperty "HKLM:\Software\Policies\Microsoft\Windows\Personalization" -Name NoLockScreenSlideshow -type DWord -Value 0x00000001 -Force
    set-itemproperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoAutorun -type DWord -Value 0x00000001 -Force
    set-itemproperty "HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0" -Name NTLMMinClientSec -type DWord -Value 0x20080000 -Force
    set-itemproperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name MinEncryptionLevel -type DWord -Value 0x00000003 -Force
    set-itemproperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name fDisableCdm -type DWord -Value 0x00000001 -Force
    set-itemproperty "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters" -Name EnableSecuritySignature -type DWord -Value 0x00000001 -Force
    # Limiting firewall log sizes
    Set-NetFirewallProfile -name domain -LogMaxSizeKilobytes 32767 -LogAllowed false -LogBlocked true
    Set-NetFirewallProfile -name private -LogMaxSizeKilobytes 32767 -LogAllowed false -LogBlocked true
    Set-NetFirewallProfile -name public -LogMaxSizeKilobytes 32767 -LogAllowed false -LogBlocked true
    # Disabling Dynamic DNS Update
    Set-ItemProperty -path HKLM:\system\currentcontrolset\services\tcpip\parameters -Name DisableDynamicUpdate -Type DWORD -value 1
}

#Call Functions to set up Windows System as per standard
DisableWindowsErrReport
SetVisualAffectReg
SetStandardReg