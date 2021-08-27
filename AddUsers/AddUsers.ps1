########################################
#                                      #
# Powershell script to import users    #
# from CSV file to Active Directory.   #
#                                      #
# Written by Gil Shwartz 2021.         #
#                                      #
########################################

#Verify User Privilleges.
If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
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

$parent = Read-Host -Prompt "Enter parent group"
if ($parent -eq "") {
        
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

	    $members = Get-ADGroupMember -Identity $User.Group -Recursive | select -ExpandProperty Name

	    if (Get-ADUser -F { SamAccountName -eq $username }) {

		Write-Warning "A user account with username $username already exists in Active Directory."

		if ($members -like $username) {
		    Write-Host "$username exsists in $group!" }

		else {  
		    Add-ADGroupMember $group -Members $username
		    }
	    }
          

    else {
	
	    Write-Host "Creating user: $username..."
        New-ADUser -SamAccountName $username -UserPrincipalName "$username@gilush.local" -Name "$firstname $lastname" -GivenName $firstname -Surname $lastname -Enabled $True -DisplayName "$lastname, $firstname" -Path $OU -AccountPassword (convertto-securestring "Ab123456!" -AsPlainText -Force) -ChangePasswordAtLogon $True
	    
        if ($members -contains $username) {
            Write-Host "$username exsists in $group!" }

        Else {  
            Add-ADGroupMember $group -Members $username 
            Write-Host "$username has been added to group: $group!"
            }
                
        echo "User $firstname $lastname Created in group: $group | OU: $OU"
        }
}
}

else {
    foreach ($User in $users){	
    
        $firstname = $User.Firstname
        $lastname = $User.Lastname
        $username = $User.SamAccountName
	    $password = $User.Password
        $group = $User.Group
	    $OU = $User.ou  
   
        $members = Get-ADGroupMember -Identity $User.Group -Recursive | select -ExpandProperty Name
               
        if (Get-ADUser -F { SamAccountName -eq $username }) {
        
            Write-Warning "A user account with username $username already exists in Active Directory."

            if ($members -like $username) {
                Write-Host "$username exsists in $group!" }

            else {  
                Add-ADGroupMember $group -Members $username
                Add-ADGroupMember $parent -Members $username
                Write-Host "User $username Added to groups: $group | $parent."
                }
        }
          

        else {
	
	        Write-Host "Creating user: $username..."
            New-ADUser -SamAccountName $username -UserPrincipalName "$username@gilush.local" -Name "$firstname $lastname" -GivenName $firstname -Surname $lastname -Enabled $True -DisplayName "$lastname, $firstname" -Path $OU -AccountPassword (convertto-securestring "Ab123456!" -AsPlainText -Force) -ChangePasswordAtLogon $True
	    
            if ($members -contains $username) {
                Write-Host "$username exsists in $group!" }

            Else {  
                Add-ADGroupMember $group -Members $username 
                Add-ADGroupMember $parent -Members $username
                Write-Host "User $username Added to groups: $group | $parent."
                }
                
            echo "User $firstname $lastname Created in group: $group | OU: $OU"
            }
    }
}


