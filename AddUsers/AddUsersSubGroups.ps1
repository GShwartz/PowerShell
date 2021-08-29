########################################
#                                      #
# Powershell script to import users    #
# from CSV file to Active Directory.   #
#                                      #
# Written by Gil Shwartz 2021.         #
#                                      #
########################################

#Verify User Privilleges.
If (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
        [Security.Principal.WindowsBuiltInRole] "Administrator"))
    {
        Write-Warning "You are not running this as local administrator. Run it again in an elevated prompt."
	    Break
    }

cls

#Import AD Module & Type.
Import-Module ActiveDirectory
Add-Type -AssemblyName System.Windows.Forms


#Load a .CSV file. 
$file = New-Object System.Windows.Forms.OpenFileDialog -Property @{
    InitialDirectory = [Environment]::GetFolderPath('Desktop')
}

#Open the file window.
$null = $file.ShowDialog()

#Place imported file in variable.
$filepath = $file.FileName
$users = Import-csv $filepath

#Show Help in header. 
Write-Host "==============================================================================="
Write-Host ""
Write-Host "Assembly group and Sorting group are departments inside the Production OU."
Write-Host "If you want the users to be added to the production group"
Write-Host "then you must type the group name as the parent group."
Write-Host "You can also add to groups outside of the parent OU for example:"
Write-Host "The group Managers is in OU=Users so type Managers as parent"
Write-Host ""
Write-Host "==============================================================================="
Write-Host ""

#Create a list of additional groups.
$parent_groups = @()

$assmgmtfuture = "OU=Assembly_MGMT_Future,OU=Assembly_MGMT,OU=Assembly,OU=Production,DC=gilush,DC=local"
$assfutureou = "OU=Assembly_Future,OU=Assembly,OU=Production,DC=gilush,DC=local"
$sortfutureou = "OU=Sorting_Future,OU=Sorting,OU=Production,DC=gilush,DC=local"
$sortmgmtfuture = "OU=Sorting_MGMT_Future,OU=Sorting_MGMT,OU=Sorting,OU=Production,DC=gilush,DC=local"

#Get additional groups names from the user.
do {
    $parent = Read-Host "Enter parent group (blank for none)" 
     
    #Check if the group exists.
    try {
        $group_exists = Get-ADGroup -Identity $parent
        $parent_groups += $parent
        Write-Host "Groups Selected: $parent_groups"
        }
        catch {
            if ($parent -eq "") {break}
            Write-Warning "Group $parent does not exists."
        }
}
#If user hits ENTER on an empty string the loop will stop.
until ($parent -eq "")

#Get input for user account status.
$ustat = $null

do {
    $user_status = Read-Host "Should the users be [E]nabled or [D]isabled?"

}
until ($user_status -like "e" -or $user_status -like "d")

if ($user_status -like "e") {
    $ustat = $True
} else {$ustat = $false}

#Check if the additional groups list is empty.
if ($parent_groups.Length -eq 0) {
    Write-Host ""
    Write-Warning "**************************************************************************************"
    Write-Warning "                            No Parent Group Selected.                                 "
    Write-Warning "**************************************************************************************"
    Write-Host ""

    #Loop through the file and get user information.
    #If the user is already configured then a message will pop
    #and the script will add the user to AD and designated groups and
    #move on to the next one.
    foreach ($User in $users){	
        $firstname = $User.Firstname
        $lastname = $User.Lastname
        $username = $User.SamAccountName
	    $password = $User.Password
        $group = $User.Group -split ";"
	    $OU = $User.ou  
        
        #Check if the user is already in Active Directory.       
        if (Get-ADUser -F { SamAccountName -eq $username }) {
            Write-Warning "A user account with username $username already exists in Active Directory." 
            foreach ($cg in $group) {
                Add-ADGroupMember $cg -Members $username 
                Write-Host "$username created in group: CSV: $cg | OU: $OU | Enabled Status: $ustat" -ForegroundColor Green
                Write-Host "$username has been added to group: $cg!" -ForegroundColor Green
            }         
        }

        else {
	        Write-Host "Creating user: $username..." -ForegroundColor White
            if ($ustat){
                New-ADUser -SamAccountName $username -UserPrincipalName "$username@gilush.local" -Name "$firstname $lastname" -GivenName $firstname -Surname $lastname -Enabled $ustat -DisplayName "$lastname, $firstname" -Path $OU -AccountPassword (convertto-securestring "Ab123456!" -AsPlainText -Force) -ChangePasswordAtLogon $True    
            }
            if (-not $ustat) {
                foreach ($grp in $group) {
                    if ($grp -like "Assembly_MGMT") {
                        if ($OU -ne $assmgmtfuture){
                            New-ADUser -SamAccountName $username -UserPrincipalName "$username@gilush.local" -Name "$firstname $lastname" -GivenName $firstname -Surname $lastname -Enabled $ustat -DisplayName "$lastname, $firstname" -Path $assmgmtfuture -AccountPassword (convertto-securestring "Ab123456!" -AsPlainText -Force) -ChangePasswordAtLogon $True
                            Write-Warning "user $username created in OU: $assmgmtfuture"
                        }
                    }
                    elseif ($grp -like "Assembly") {
                        New-ADUser -SamAccountName $username -UserPrincipalName "$username@gilush.local" -Name "$firstname $lastname" -GivenName $firstname -Surname $lastname -Enabled $ustat -DisplayName "$lastname, $firstname" -Path $assfutureou -AccountPassword (convertto-securestring "Ab123456!" -AsPlainText -Force) -ChangePasswordAtLogon $True
                        Write-Warning "user $username created in OU: $assfutureou"
                    }
                    elseif ($grp -like "Sorting_MGMT") {
                        if ($OU -ne $sortmgmtfuture) {
                            New-ADUser -SamAccountName $username -UserPrincipalName "$username@gilush.local" -Name "$firstname $lastname" -GivenName $firstname -Surname $lastname -Enabled $ustat -DisplayName "$lastname, $firstname" -Path $sortmgmtfuture -AccountPassword (convertto-securestring "Ab123456!" -AsPlainText -Force) -ChangePasswordAtLogon $True
                            Write-Warning "user $username created in OU: $sortmgmtfuture"
                        }
                    }
                    elseif ($grp -like "Sorting") {
                        New-ADUser -SamAccountName $username -UserPrincipalName "$username@gilush.local" -Name "$firstname $lastname" -GivenName $firstname -Surname $lastname -Enabled $ustat -DisplayName "$lastname, $firstname" -Path $sortfutureou -AccountPassword (convertto-securestring "Ab123456!" -AsPlainText -Force) -ChangePasswordAtLogon $True
                        Write-Warning "user $username created in OU: $sortfutureou"
                    }
                }
            }
        }

        foreach ($cg in $group) {
            Add-ADGroupMember ($cg + "_Future") -Members $username 
            Write-Host ("User $username created in group: CSV: $cg _Future | OU: $OU | Enabled: $ustat") -ForegroundColor Green
        }
    }
}

else {
    #Loop through the file and get user information.
    #If the user is already configured then a message will pop
    #and the script will add the user to AD and designated groups and
    #move on to the next one.
    foreach ($User in $users){
        $firstname = $User.Firstname
        $lastname = $User.Lastname
        $username = $User.SamAccountName
	    $password = $User.Password
        $group = $User.Group -split ";"
	    $OU = $User.ou
            
        try {
    	    Write-Host "Creating user: $username..." -ForegroundColor White
            New-ADUser -SamAccountName $username -UserPrincipalName "$username@gilush.local" -Name "$firstname $lastname" -GivenName $firstname -Surname $lastname -Enabled $ustat -DisplayName "$lastname, $firstname" -Path $OU -AccountPassword (convertto-securestring "Ab123456!" -AsPlainText -Force) -ChangePasswordAtLogon $True                     
            Write-Host "User $firstname $lastname Created in OU: $OU" -ForegroundColor Green 
        } catch {
            Write-Warning "User $username already in AD."
            }

        #Loop through the additional groups list and add the user.
        foreach ($g in $parent_groups) {	
            Add-ADGroupMember $g -Members $username
        
        #Summerize action to terminal output.
        Write-Host "User $username Added to groups: CSV: $group | Additional: $g." -ForegroundColor Green
        }
        foreach ($csv_g in $group) {
            Add-ADGroupMember $csv_g -Members $username 
        }
    }
}
