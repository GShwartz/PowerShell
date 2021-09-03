#Verify User Privilleges.
If (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
        [Security.Principal.WindowsBuiltInRole] "Administrator"))
    {
        Write-Host "Run as Administrator." -ForegroundColor Red
	    Break
    }

#Import AD Module & Type.
Import-Module ActiveDirectory
Add-Type -AssemblyName System.Windows.Forms

#Load a .CSV file.
$file = New-Object System.Windows.Forms.OpenFileDialog -Property @{
    InitialDirectory = [Environment]::GetFolderPath('Desktop')
}
$null = $file.ShowDialog()
$filepath = $file.FileName
$users = Import-csv $filepath

#Gather local information.
$domain = Get-ADDomain -Current LocalComputer | Select-Object DistinguishedName -ExpandProperty DistinguishedName
$hostname = [System.Net.Dns]::GetHostName()
$dnsroot = Get-ADForest -Current LocalComputer | Select-Object Name -ExpandProperty Name
$serverdns = Get-DnsServer -ComputerName $hostname -WarningAction SilentlyContinue

#Show Help in header. 
Write-Host "==============================================================================="
Write-Host "You can add the users to additional groups"
Write-Host "==============================================================================="
Write-Host ""

#Get additional groups names from the user.
$parent_groups = @()

do {
    $parent = Read-Host "Enter additional group (blank for none)" 
    
    #Check if the group exists.
    try {
        $group_exists = Get-ADGroup -Identity $parent
        if ($parent -in $parent_groups) {
            Write-Warning "$parent already added."
        }
        else {$parent_groups += $parent}

        Write-Host "Groups Selected: $parent_groups"
        
    }
    catch {if ($parent -eq "") {break}}
}
until ($parent -eq "") #If user hits ENTER on an empty string the loop will stop.

#Get input for user account status.
$ustat = $null

do {
    $user_status = Read-Host "[E]nabled | [D]isabled"

}
until ($user_status -like "e" -or $user_status -like "d")

if ($user_status -like "e") {
    $ustat = $True
} else {$ustat = $false}

#Check if the additional groups list is empty.
if ($parent_groups.Length -eq 0) {
    #Show Warning
    Write-Warning "**************************************************************************************"
    Write-Warning "                            No Parent Group Selected.                                 "
    Write-Warning "**************************************************************************************"
}

[System.Collections.ArrayList]$GrpList = @()

#Add users.
foreach ($User in $users){	
    $firstname = $User.Firstname
    $lastname = $User.Lastname
    $username = $User.SamAccountName
	$password = $User.Password
    $group = $User.Group

    foreach ($g in $group -split ";") {
        if ($g -in $GrpList) {continue}
        else {$GrpList += $g}

    }
        
    #Check if the user is already in Active Directory.       
    if (Get-ADUser -F { SamAccountName -eq $username } -WarningAction SilentlyContinue) {
        Write-Warning "A user account with username $username already exists in Active Directory." 
                
        foreach ($g in $group -split ";") {
            Add-ADGroupMember $g -Members $username 

        }
    }
    else {
        $ou = Get-ADOrganizationalUnit -LDAPFilter "(name=$($g))" -SearchBase $domain -SearchScope 2 | Select-Object DistinguishedName -ExpandProperty DistinguishedName
                        
        Write-Host "Creating user: $username..." -ForegroundColor White

        if ($GrpList.Count -gt 1) {
            foreach ($g in $group -split ";") {
                if (Get-ADUser -F { SamAccountName -eq $username } -WarningAction SilentlyContinue) {continue}
                    New-ADUser -SamAccountName $username -UserPrincipalName "$username@$domain" -Name "$firstname $lastname" -GivenName $firstname -Surname $lastname -DisplayName "$lastname, $firstname" -Path $ou -Enabled $ustat -AccountPassword (convertto-securestring $password -AsPlainText -Force) -ChangePasswordAtLogon $True
                    Add-ADGroupMember $g -Members $username 
                    $GrpList.Remove($g)
            }
        } 
    
        if ($parent_groups.Count -gt 0) {
            foreach ($p in $parent_groups) {
                Add-ADGroupMember $p -Members $username
            
            }
        }

        Write-Host ("$username created in group: $g | Additional groups: $parent_groups | OU: $ou | Enabled: $ustat") -ForegroundColor Green
    }
}
