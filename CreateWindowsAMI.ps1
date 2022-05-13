

Param(
	[Parameter(Mandatory=$true)]
    [String]$amiNamePrefix,
    [Parameter(Mandatory=$false)]
    [ValidateSet("us-east-1","us-east-2","us-west-1","us-west-2")]
    [String]$region = "us-east-1",    
    [Parameter(Mandatory=$false)]
    [String]$vpcId,
    [Parameter(Mandatory=$true)]
    [String]$subnetId,
    [Parameter(Mandatory=$true)]
    [String]$securityGroupId
)

# Function to create template definition json file for Packer
Function Create-JsonTemplate()
{
    Try{	
    $input1 = @"
    {
        "variables": {
            "access_key": "",
            "secret_key": ""
        },
        "builders": [{
            "type": "amazon-ebs",        
            "access_key": "{{user ``access_key``}}",
            "secret_key": "{{user ``secret_key``}}",
            "ami_name": "$($amiName)",
            "vpc_id": "$($vpcId)",
            "subnet_id": "$($subnetId)",
            "security_group_id":"$($securityGroupId)",
            "region": "$($region)",
            "source_ami_filter": {
                "filters": {
                  "virtualization-type": "hvm",
                  "name": "Windows_Server-2019-English-Full-Base-*",
                  "root-device-type": "ebs"
                },
                "owners": ["amazon"],
                "most_recent": true
              },
            "instance_type": "t2.medium",
            "ami_description": "Windows 2019 AMI",
            "disable_stop_instance": "false",
            "ssh_keypair_name": "windows",
            "ssh_private_key_file": "./windows.pem",
            "communicator": "winrm",
            "winrm_username": "Administrator",
            "winrm_timeout": "30m",              
            "winrm_insecure": true,
            "winrm_use_ssl": true,
            "winrm_port": "5986",
            "user_data_file":"./userdata.txt",

            "launch_block_device_mappings": [
               	{
                   	"device_name": "/dev/sda1",
                   	"volume_type": "gp2",
                   	"delete_on_termination": true
               	}
            ],
	        "run_tags": {
                "Name": "Packer Builder",
                "OsType": "Windows",
                "CreationDate": "$((Get-Date).ToString("dd-MMM-yyyy"))",
                "Owner": "dmcgovern"
            },
            "tags": {
                "CreationDate": "$((Get-Date).ToString("dd-MMM-yyyy"))",
                "OsType": "Windows",
                "Owner": "dmcgovern",
                "Name": "$($amiName)"
            }
          }],
          "provisioners": [
            {
                "type": "powershell",    
                "script": "./configAMI.ps1"      
            },
            {
                "type": "powershell",    
                "script": "./install.ps1"      
            },
            {
                "type": "windows-restart",
                "restart_timeout": "10m"
            },  
            {
                "type": "powershell",
                "inline": [	
                    "C:\\ProgramData\\Amazon\\EC2-Windows\\Launch\\Scripts\\InitializeInstance.ps1 -Schedule",	
                    "C:\\ProgramData\\Amazon\\EC2-Windows\\Launch\\Scripts\\SysprepInstance.ps1 -NoShutdown"
                ]
            }
          ]
    }	
"@ 
    $input1 | Out-File $jsonTemplateFile -Encoding ascii
    }
    Catch
    {
        Write-Host "ERROR : $_" -Foregroundcolor Red
        Exit
    }
}

# Function to create Image using Packer
Function Create-Image(){
    Try{
        powershell packer build -var "access_key=$($accessKey)" -var "secret_key=$($secretKey)" $jsonTemplateFile 
    }
    Catch
    {
        Write-Host "ERROR : $_" -Foregroundcolor Red
        Exit
    }
}

# Function to remove resources created during the image creation process
Function Cleanup-Resources(){
    Try{
        Write-Host "Deleting Template JSON file"
        if(Test-Path -Path $jsonTemplateFile){
            Remove-Item -Path $jsonTemplateFile -Force
        }
    }
    Catch{
        Write-Host "ERROR : $_" -Foregroundcolor Red
    }
}

# Check AWS Secrets are configured as Environment Variable. If not either set those or use alternate method to pass those secrets.
# If you use a different method, like user Profile, File or any other method comment out below script block.
if((Test-Path -Path Env:\AWS_ACCESS_KEY_ID) -and (Test-Path -Path Env:\AWS_SECRET_ACCESS_KEY)){
    $accessKey = $Env:AWS_ACCESS_KEY_ID
    $secretKey = $Env:AWS_SECRET_ACCESS_KEY
}
else{
    Write-Host "ERROR : AWS Credentials are not set as Environment Variables. Either set those or use different method to pass those values.If you use alternate method.Comment this Block" -ForegroundColor Yellow
    Exit
}

# Check if passed VPCId exists in the AWS Account, if not Exit
$vpcInfo = Get-EC2Vpc -VpcId $vpcId -Region $region -AccessKey $accessKey -SecretKey $secretKey
if([String]::IsNullOrEmpty($vpcInfo)){
    Write-Host "ERROR : Incorrect VPC ID Supplied. Exiting.."
    Exit
}

# Check if passed SubnetId exists in the AWS Account, if not Exit
$subnetInfo = Get-EC2Subnet -SubnetId $subnetId -Region $region -AccessKey $accessKey -SecretKey $secretKey
if([String]::IsNullOrEmpty($subnetInfo)){
    Write-Host "ERROR : Incorrect Subnet ID Supplied. Exiting.."
    Exit
}
# Check if passed SecurityGroupId exists in the AWS Account, if not Exit
$sgInfo = Get-EC2SecurityGroup -GroupId $securityGroupId -Region $region -AccessKey $accessKey -SecretKey $secretKey
if([String]::IsNullOrEmpty($sgInfo)){
    Write-Host "ERROR : Incorrect Subnet ID Supplied. Exiting.."
    Exit
}

$jsonTemplateFile = "$($env:Temp)\image-template.json"
if(Test-Path $jsonTemplateFile){Remove-Item -Path $jsonTemplateFile -Force}

# Generate AMI Name. Check if an AMI already exists with that name. If so, suffix name with random letters
$amiName = "$($amiNamePrefix)-Windows2019-$((Get-Date).ToString("dd-MMM-yyyy"))"
#$awsAccount = Get-STSCallerIdentity | Select-Object Account -ExpandProperty Account
#$amiDetails = Get-EC2Image -AccessKey $accessKey -SecretKey $secretKey -Region $region -Filter @{ Name="name"; Values=$amiName} -Owner $awsAccount -ErrorAction SilentlyContinue

if(!([String]::IsNullOrEmpty($amiDetails))){
    $amiName = "$($amiName)-$(-join ((12..34) + (56..789) | Get-Random -Count 6 | ForEach-Object {[char]$_}))"
}

Create-JsonTemplate 
Create-Image

$amiDetails = Get-EC2Image -AccessKey $accessKey -SecretKey $secretKey -Region $region -Filter @{ Name="name"; Values=$amiName} -Owner $awsAccount -ErrorAction SilentlyContinue
if(!([String]::IsNullOrEmpty($amiDetails))){
    Write-Host "New Image $($amiName)($($amiDetails.ImageId)) created successfully!" -ForegroundColor Green
}
else{
    Write-Host "ERROR : Something went wrong! Please try again!" -ForegroundColor Red
}
Cleanup-Resources

#test commit