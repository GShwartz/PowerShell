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
$help = $false
 
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

$parent = Read-Host "Enter parent group (blank for none)"  

if ($parent -eq "") {
    Write-Host "[!]NO PARENT GROUP[!]"

    #Loop through the file and get user information.
    #If the user is already configured then a message will pop
    #and the script will add the user to AD and designated groups and
    #move on to the next one.

    foreach ($User in $users){	
    
        $firstname = $User.Firstname
        $lastname = $User.Lastname
        $username = $User.SamAccountName
	    $password = $User.Password
        $group = $User.Group
	    $OU = $User.ou  
               
        if (Get-ADUser -F { SamAccountName -eq $username }) {
        
            Write-Warning "A user account with username $username already exists in Active Directory."          
        }
          

            else {
	
	            Write-Host "Creating user: $username..." -ForegroundColor White
                New-ADUser -SamAccountName $username -UserPrincipalName "$username@gilush.local" -Name "$firstname $lastname" -GivenName $firstname -Surname $lastname -Enabled $True -DisplayName "$lastname, $firstname" -Path $OU -AccountPassword (convertto-securestring "Ab123456!" -AsPlainText -Force) -ChangePasswordAtLogon $True
	    
                if ($members -contains $username) {
                    Write-Host "$username exsists in $group!" }

                Else {  
                    Add-ADGroupMember $group -Members $username 
                    Write-Host "$username has been added to group: $group!" -ForegroundColor Green
                    }
                
                Write-Host "User $firstname $lastname Created in group: $group | OU: $OU" -ForegroundColor Green
                }
    }
}

    else {
        
        try {$group_exists = Get-ADGroup -Identity $parent}
            catch {
                Write-Warning "Group $group_exists does not exists."
            }

        if ($group_exists) { 
            
            foreach ($User in $users){	
    
                $firstname = $User.Firstname
                $lastname = $User.Lastname
                $username = $User.SamAccountName
	            $password = $User.Password
                $group = $User.Group
	            $OU = $User.ou  
                  
                if (Get-ADUser -F { SamAccountName -eq $username }) {
            
                    Write-Warning "A user account with username $username already exists in Active Directory."                
                    Add-ADGroupMember $group -Members $username 
                    Add-ADGroupMember $parent -Members $username
                    Write-Host "User $username Added to groups: CSV: $group | Parent: $parent." -ForegroundColor Green
                }
            

                    else {
	
	                    Write-Host "Creating user: $username..." -ForegroundColor White
                        New-ADUser -SamAccountName $username -UserPrincipalName "$username@gilush.local" -Name "$firstname $lastname" -GivenName $firstname -Surname $lastname -Enabled $True -DisplayName "$lastname, $firstname" -Path $OU -AccountPassword (convertto-securestring "Ab123456!" -AsPlainText -Force) -ChangePasswordAtLogon $True                     
                        Add-ADGroupMember $group -Members $username 
                        Add-ADGroupMember $parent -Members $username   
                        Write-Host "User $firstname $lastname Created in OU: $OU" -ForegroundColor Green 
                        Write-Host "User $username Added to groups: $group | $parent." -ForegroundColor Green

                        }
            }
        }
            else {
                
                Write-Warning "No parent group selected, adding from file..."

                foreach ($User in $users){	
    
                $firstname = $User.Firstname
                $lastname = $User.Lastname
                $username = $User.SamAccountName
	            $password = $User.Password
                $group = $User.Group
	            $OU = $User.ou  
                  
                if (Get-ADUser -F { SamAccountName -eq $username }) {
            
                    Write-Warning "A user account with username $username already exists in Active Directory."                
                    Add-ADGroupMember $group -Members $username 
                    Write-Host "User $username Added to group: $group." -ForegroundColor Green
                }
            
                    else {
	
	                    Write-Host "Creating user: $username..." -ForegroundColor White
                        New-ADUser -SamAccountName $username -UserPrincipalName "$username@gilush.local" -Name "$firstname $lastname" -GivenName $firstname -Surname $lastname -Enabled $True -DisplayName "$lastname, $firstname" -Path $OU -AccountPassword (convertto-securestring "Ab123456!" -AsPlainText -Force) -ChangePasswordAtLogon $True                     
                        Add-ADGroupMember $group -Members $username 
                        Write-Host "User $firstname $lastname Created in OU: $OU" -ForegroundColor Green
                        Write-Host "User $username Added to group: $group." -ForegroundColor Green   
                        
                        }
            }
    }
}