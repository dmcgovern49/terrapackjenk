# Cloudwatch agent install
$parameters = @{
    Uri = 'https://s3.amazonaws.com/amazoncloudwatch-agent/windows/amd64/latest/AmazonCloudWatchAgent.zip'
    OutFile = "$env:TEMP\AmazonCloudWatchAgent.zip"
}
Invoke-WebRequest @parameters

Expand-Archive -Path "$env:TEMP\AmazonCloudWatchAgent.zip" -DestinationPath "$env:TEMP\AmazonCloudWatchAgent"

Set-Location -Path "$env:TEMP\AmazonCloudWatchAgent"

.\install.ps1

#SSM INSTALL

Invoke-WebRequest https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/windows_amd64/AmazonSSMAgentSetup.exe -OutFile $env:USERPROFILE\Desktop\SSMAgent_latest.exe

Start-Process -FilePath $env:USERPROFILE\Desktop\SSMAgent_latest.exe -ArgumentList "/S"

Restart-Service AmazonSSMAgent


#AWS CLI install
$dlurl = "https://awscli.amazonaws.com/AWSCLIV2.msi"
$installerPath = Join-Path $env:TEMP (Split-Path $dlurl -Leaf)
Invoke-WebRequest $dlurl -OutFile $installerPath
Start-Process -FilePath msiexec -Args "/qn /i $installerPath /passive" -Verb RunAs -Wait
Remove-Item $installerPath
$env:Path += ";C:\Program Files\Amazon\AWSCLI\bin"



#Install Chrome
$LocalTempDir = $env:TEMP; $ChromeInstaller = "ChromeInstaller.exe"; (new-object    System.Net.WebClient).DownloadFile('http://dl.google.com/chrome/install/375.126/chrome_installer.exe', "$LocalTempDir\$ChromeInstaller"); & "$LocalTempDir\$ChromeInstaller" /silent /install; $Process2Monitor =  "ChromeInstaller"; Do { $ProcessesFound = Get-Process | ?{$Process2Monitor -contains $_.Name} | Select-Object -ExpandProperty Name; If ($ProcessesFound) { "Still running: $($ProcessesFound -join ', ')" | Write-Host; Start-Sleep -Seconds 2 } else { rm "$LocalTempDir\$ChromeInstaller" -ErrorAction SilentlyContinue -Verbose } } Until (!$ProcessesFound)

