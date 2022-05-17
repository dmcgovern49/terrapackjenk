$Banner = @"
You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

- At any time, the USG may inspect and seize data stored on this IS.

- Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

- This IS includes security measures (e.g., authentication and access controls) to protect USG interests—not for your personal benefit or privacy.

- Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.
"@ 

function WS2019(){
    #V-205629
    set-itemproperty "HKLM:\\SYSTEM\CurrentControlSet\Services\RemoteAccess\Parameters\AccountLockout" -name MaxDenials -type DWord -value 3
    #V-205630
    set-itemproperty "HKLM:\\SYSTEM\CurrentControlSet\Services\RemoteAccess\Parameters\AccountLockout" -name "ResetTime (mins)" -type DWORD -value 15
    #V-205631
    set-itemproperty "HKLM:\\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -name LegalNoticeTest -value $Banner
    #V-205632 
    set-itemproperty "HKLM:\\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -name LegalNoticeCaption -value $Banner
    #V-205633
    set-itemproperty "HKLM:\\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -name InactivityTimeoutSecs -type DWord -value 0x00000384
    #V-205636
    set-itemproperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -name fEncryptRPCTraffic -type DWord -Value 1
    #V-205637
    set-itemproperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -name MinEncryptionLevel -type DWord -Value 3
    #V-205638
    set-itemproperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\" -name ProcessCreationIncludeCmdLine_Enabled -type DWord -value 1
    #V-205639
    set-itemproperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\" -name EnableScriptBlockLogging -type DWord -value 1
    #V-205640, 205641, 205642,  Default setttings are already STIGd.
    #V-205643 needs to performs by GPO after the system joins the domain. Apply these settings before will make the system unuseable.
    #V-205644
    set-itemproperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -name SCENoApplyLegacyAuditPolicy -type DWord -value 1
    #V-205645, need to obtain server cert from dc.
    #V-205646, need to obtain server cert from dc that issued by DOD. 
    #V-205647, Map PKI user accounts to PKI cerificates using appropriate UPN like 1234567890@mil
    #V-205648, Install DoD Root CA
    #V-205649, Install the DoD Interoperability Root CA cross-certificates.
    #V-205650, Install the US DoD CCEB Interoperability Root CA cross-certificate
    #V-205651
    set-itemproperty "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\" -name ForceKeyProtection -type DWord -value 2
    #V-205652 PasswordComplexity = 1, default setting is STIG.
    #V-205653 ClearTextPassword =1. default setting is STIG.
    #V-205654
    set-itemproperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -name NoLMHash -type DWord -value 1
    #V-205655
    set-itemproperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\" -name EnablePlainTextPassword -type DWord -value 0
    #V-205656 Needs to do by gpo, having a hard time finding it in REG.
    #V-205657 LAPS for local admin password.
    #V-205658 Passwords must expire.
    #V-205659 set to 42 by default which is stigd.
    #V-205660
   # net accounts /uniquepw:24
    #V-205661 Establish a policy that requires application/service account passwords that are manually managed to be at least 15 characters in length. Ensure the policy is enforced.
    #V-205662
    #net accounts /MINPWLEN:14
    #V-205663 Format volumes to use NTFS or ReFS.
    #V-205664 Default is stig.
    #V-205665, 205666, 205667, 205668, 205669 apply to DCs.
    #V-205670
    #Get-LocalUser Guest | Disable-LocalUser
    #V-205674 has to been by GPO, once joined to the domain.
    #V-205677 Document the roles and features required for the system to operate. Uninstall any that are not required.
    #V-205678 fax server is not installed at default.
    #V-205679 PNRP is not installed at default.
    #V-205680 Simple-TCPIP is not installed at default.
    #V-205681 TFTP-Client is not installed.
    #V-205682 FS-SMB1 is not installed.
    #V-205683
    set-itemproperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\" -name MB1 -type Dword -value 0
    #V-205684 set-itemproperty "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10\" -name Start -type Dword -value 4
    #V-205685 Powershell-v2 is removed at default.
    #V-205686
    set-itemproperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization\" -name NoLockScreenSlideshow -type Dword -value 1
    #V-205687
    set-itemproperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest\" -name UseLogonCredential -type Dword -value 0
    #V-205688
    set-itemproperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\" -name DisableWebPnPDownload -type Dword -value 1
    #V-205689
    set-itemproperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\" -name DisableHTTPPrinting -type Dword -value 1
    #V-205690
    set-itemproperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\" -name DontDisplayNetworkSelectionUI -type Dword -value 1
    #V-205691
    set-itemproperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat\" -name DisableInventory -type DWord -value 1
    #V-205692
    set-itemproperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\" -name EnableSmartScreen -type DWord -value 1
    #V-205693
    set-itemproperty "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds\" -name AllowBasicAuthInClear -type DWord -value 0
    #V-205694
    set-itemproperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search\" -name AllowIndexingEncryptedStoresOrItems -type Dword -value 0
    #V-205695 applies to DCs.
    #V-205696
    set-itemproperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\" -name EnumerateLocalUsers -type Dword -value 0
    # V-205697 FTP Service is not installed.
    #V-205698 Telnet-Client is not installed.
    #V-205699 shared accounts?
    #V-205700 Configure all enabled accounts to require password
    #V-205701, 205702, 205703, 205704, 205705, 205706 Applies to DCs.
    #V-205707 Regularly review accounts to determine if they are still active. Remove or disable accounts that have not been used in the last 35 days.
    #V-205708
    set-itemproperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\" -name SupportedEncryptionTypes -type DWord -Value 0x7ffffff8
    #V-205710 Remove emergency administrator accounts after a crisis has been resolved or configure the accounts to automatically expire within 72 hours.
    #V-205711
    set-itemproperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\" -name AllowBasic -type Dword -value 0
    #V-205712
    set-itemproperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\" -name AllowDigest -type Dword -value 0
    #V-205713
    set-itemproperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\" -name AllowBasic -type Dword -value 0
    #V-205714
    set-itemproperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\" -name EnumerateAdministrators -type Dword -value 0
    #V-205715
    set-itemproperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -name LocalAccountTokenFilterPolicy -type Dword -value 0
    #V-205716
    set-itemproperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -name EnableUIADesktopToggle -type Dword -value 0
    #V-205717
    set-itemproperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -name ConsentPromptBehaviorAdmin -type Dword -value 2
    #V-205718
    set-itemproperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -name EnableInstallerDetection -type Dword -value 1
    #V-205719
    set-itemproperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -name EnableSecureUIAPaths -type Dword -value 1
    #V-205720
    set-itemproperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -name EnableVirtualization -type Dword -value 1
    #V-205721 Remove any unnecessary non-system-created shares
    #V-205722
    set-itemproperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" -name fDisableCdm -type Dword -value 1
    #V-205723  The parameter do not exist.
    #V-205724
    set-itemproperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -name RestrictAnonymous -type Dword -value 1
    #V-205725
    set-itemproperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\" -name RestrictNullSessAccess -type Dword -value 1
    #V-205726 applies to DCs.
    #V-205727 data at rest protections must employ.
    #V-205728 Install a DoD-approved ESS software and ensure it is operating continuously.
    #V-205731 Default permissions are stigd.
    #V-205734 Defualt permissions are stigd.
    #V-205735 Defualt permissions are stigd.
    #V-205736 Default permissions are stigd.
    #V-205737 defaults have not been changed, these are not a finding.
    #V-205738, 205739, 205740, 205742, 205743, 205744, 205745,  applies to DCs.
    #V-205785 205786, 205787, 205788, 205789, 205790, 205791, 205792, 205793, 205794, applies to DCs.
    #V-205796
    set-itemproperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" -name MaxSize -type DWord -value 32768
    #V-205797
    set-itemproperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" -name MaxSize -type DWord -value 196608
    #V-205798
    set-itemproperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" -name MaxSize -type DWord -value 32768
    #V-205801
    set-itemproperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\" -name EnableUserControl -type DWord -value 0
    #V-205802
    set-itemproperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\" -name AlwaysInstallElevated -type Dword -value 0
    #V-205803 Monitor the system for unauthorized changes to system files (e.g., *.exe, *.bat, *.com, *.cmd, and *.dll) against a baseline on a weekly basis. This can be done with the use of various monitoring tools.
    #V-205804
    set-itemproperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -name NoAutoplayfornonVolume -type Dword -value 1
    #V-205805
    set-itemproperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\" -name NoAutoRun -type Dword -value 1
    #V-205806
    set-itemproperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\" -name NoDriveTypeAutoRun -type Dword -value 255
    #V-205807 Implementation guidance for AppLocker is available in the NSA paper "Application Whitelisting using Microsoft AppLocker" at the following link: https://www.iad.gov/iad/library/ia-guidance/tech-briefs/application-whitelisting-using-microsoft-applocker.cfm
    #V-205808
    set-itemproperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" -name DisablePasswordSaving -type Dword -value 1
    #V-205809
    set-itemproperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" -name fPromptforPassword -type Dword -value 1
    #V-205810
    set-itemproperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\" -name DisableRunAs -type Dword -value 1
    #V-205811
    set-itemproperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -name FilterAdministratorToken -type dword -value 1
    #V-205812
    set-itemproperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -name ConsentPromptBehaviorUser -type dword -value 0
    #V-205813
    set-itemproperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -name EnableLUA -type dword -value 1
    #V-205814
    set-itemproperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc\" -name RestrctRemoteClients -type dword -value 1
    #V-205815
    set-itemproperty "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -name DisablePasswordChange -type dword -value 0
    #V-205816
    set-itemproperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\" -name AllowUnencryptedTraffic -type Dword -value 0
    #V-205817
    set-itemproperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\" -name AllowUnencryptedTraffic -type Dword -value 0
    #V-205819
    set-itemproperty "HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters\" -name NoNameReleaseOnDemand -type Dword  -value 1
    #V-205821
    set-itemproperty "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\" -name RequireSignOrSeal -type Dword -value 1
    #V-205822
    set-itemproperty "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\" -name SealSecureChannel -type Dword -value 1
    #V-205823
    set-itemproperty "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\" -name SignSecureChannel -type Dword -value 1
    #V-205524
    set-itemproperty "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\" -name RequireStrongKey -type Dword -value 1
    #V-205825
    set-itemproperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\" -name RequireSecuritySignature -type Dword -value 1
    #V-205826
    set-itemproperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\" -name EnableSecuritySignature -type dword -value 1
    #V-205827
    set-itemproperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\" -name RequireSecuritySignature -type dword -value 1
    #V-205828
    set-itemproperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\" -name EnableSecuritySignature -type dword -value 1
    #V-205830
    set-itemproperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\" -name NoDataExecutionPrevention -type dword -value 0
    #V-205842
    set-itemproperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\" -name Enabled -type dword -value 1
    #V-205858
    
    #V-205818,205820 applies to DCs, 
    set-itemproperty "HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters\" -Name NoNameReleaseOnDemand -type DWord -Value 0x00000001 -Force
    #V-205829
    #V-205843 Configure the system to, at a minimum, off-load audit records of interconnected systems in real time and off-load standalone systems weekly.
    #V-205844 Ensure each user with administrative privileges has a separate account for user duties and one for privileged duties.
    #V-205845 Establish a policy, at minimum, to prohibit administrative accounts from using applications that access the Internet, such as web browsers, or with potential Internet sources, such as email. Ensure the policy is enforced.
    #V-205747
    set-itemproperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name RestrictRemoteSAM -Value "O:BAG:BAD:(A;;RC;;;BA)" -Force
    #V-205848 Ensure domain-joined systems have a TPM that is configured for use. (Versions 2.0 or 1.2 support Credential Guard.)
    #V-205849 Preview versions must not be used in a production environment.
    #V-205851 Install a HIDS or HIPS on each server.
    #V-205857 secureboot is not supported.
    #V-205858
    set-itemproperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\" -Name DisableIPSourceRouting -type DWord -Value 0x00000002 -Force
    #V-205859
    set-itemproperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\" -Name DisableIPSourceRouting -type DWord -Value 0x00000002 -Force
    #V-205860
    set-itemproperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\" -Name EnableICMPRedirect -type DWORD -Value 0
    #V-205861
    set-itemproperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\" -name AllowInsecureGuestAuth -type Dword -value 0
    #V-205863
    set-itemproperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\" -name AllowProtectedCreds -type Dword -value 1
    #V-205865
    set-itemproperty "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\" -name DriveLoadPolicy -type dword -value 3
    #V-205867
    set-itemproperty "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\" -name DCSettingIndex -type dword -value 1
    #V-205868
    set-itemproperty "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\" -name ACSettingIndex -type dword -value 1
    #V-205869
    set-itemproperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection\" -name AllowTelemetry -type dword -value 1
    #V-205870
    #set-itemproperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization\" -name DODownloadMode -type dword -value 2
    #V-205871
    set-itemproperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\" -Name NoHeapTerminationOnCorruption -type dword -value 0
    #V-205872 default is stig
    #V-205873
    set-itemproperty "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds\" -name DisableEnclosureDownload -type dword -value 1
    #V-205874 default is stig.
    #V-205906
    set-itemproperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -name CachedLogonCount -value 4
    #V-205908
    set-itemproperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -name LimitBlankPasswordUse -type dword -value 1
    #V-205911
    set-itemproperty "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -name MaximumPasswordAge -type dword -value 30
    #V-205912 get with isso.
    #set-itemproperty "HKLM:\SOFTWARE\Microsoft\Windows\Windows NT\CurrentVersion\Winlogon\" -name scremoveoption
    #V-205914
    set-itemproperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -name RestrictAnonymousSAM -type dword -value 1
    #V-205915
    set-itemproperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -name EveryoneIncludesAnonymous -type dword -value 0
    #V-205916
    set-itemproperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -name UseMachineId -type dword -value 1
    #V-205917
    set-itemproperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\" -name allownullsessionfallback -type dword -value 0
    #V-205918
    set-itemproperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\pku2u\" -name AllowOnlineId -type dword -value 0
    #V-205919
    set-itemproperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -name LmCompatibilityLevel -type dword -value 5
    #V-205920
    set-itemproperty "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP\" -name LDAPClientIntegrity -type dword -value 1
    #V-205921
    set-itemproperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -name NTLMMinClientSec -type dword -value 537395200
    #V-205922
    set-itemproperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -name NTLMMinServerSec -type dword -value 537395200
    #V-205923
    set-itemproperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -name ProtectionMode -type dword -value 1
    #V-205924
    set-itemproperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" -name SaveZoneInformation -type dword -value 2
    #V-205925
    set-itemproperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -name DisableAutomaticRestartSignOn -type dword -value 1
    #V-236001 
    set-itemproperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -name NoPreviewPane -type dword -value 1

    #V-214936 install and enable a host-based firewall on the system.
}

function auditpol() {
    $Success = @("Security Group Management","Computer Account Management","Other Account Management Events","Process Creation","Authentication Policy Change","Authorization Policy Change","Security State Change","Security System Extension","Group Membership","Special Logon","Logoff","Plug and Play Events")
    $Failure = @("User Account Management","Logon","Account Lockout","Audit Policy Change","Sensitive Policy Change","IPsec Driver","Other System Events", "System Integrity","Credentail Validation","Other Object Access Events","Removable Storage")

    Foreach ($S in $Success){
        auditpol /set /subcategory:$S /success:enable
    }
    Foreach ($F in $Failure){
        auditPol /set /subcategory:$F /success:enable /failure:enable
    }

}

#Call Functions to set up Windows System as per standard
WS2019
auditpol
