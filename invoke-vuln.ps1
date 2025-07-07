$Global:Domain = (Get-ADDomain).DNSRoot
$Global:CreatedUsers = Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName
$Global:BadPasswords = @("Spring2024!", "Password123!", "Changeme123!", "12345678", "Qwerty!@#")
$Global:ServicesAccountsAndSPNs = @(
    "svcsql,sql01",
    "svciis,web01",
    "svcbackup,backup01",
    "svcmail,mail01"
)
$Global:NormalGroups = @("Users")
$Global:MidGroups = @("IT", "HR", "Finance")
$Global:HighGroups = @("Domain Admins", "Enterprise Admins")
$Global:AllObjects = $Global:NormalGroups + $Global:MidGroups + $Global:HighGroups
$Global:BadACL = @("GenericAll", "GenericWrite", "WriteOwner", "WriteDacl", "WriteProperty", "All")

foreach ($g in $Global:MidGroups) {
    if (-not (Get-ADGroup -Filter "Name -eq '$g'")) {
        New-ADGroup -Name $g -GroupScope Global -Path "CN=Users,DC=impact,DC=local" | Out-Null
    }
}

function VulnAD-GetRandom {
    param ([array]$InputList)
    return $InputList | Get-Random
}

function VulnAD-AddACL {
    param (
        [string]$Source,
        [string]$Destination,
        [string]$Rights
    )
    try {
        $Identity = New-Object System.Security.Principal.SecurityIdentifier($Source)
        $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $Identity, $Rights, "Allow"
        )
        $entry = [ADSI]"LDAP://$Destination"
        $entry.ObjectSecurity.AddAccessRule($ACE)
        $entry.commitchanges()
    } catch {
        Write-Warning "Falha ao adicionar ACL de $Source para $Destination com direito $Rights"
    }
}

function VulnAD-BadAcls {
    foreach ($abuse in $Global:BadACL) {
        $ngroup = VulnAD-GetRandom -InputList $Global:NormalGroups
        $mgroup = VulnAD-GetRandom -InputList $Global:MidGroups
        $DstGroup = Get-ADGroup -Identity $mgroup
        $SrcGroup = Get-ADGroup -Identity $ngroup
        VulnAD-AddACL -Source $SrcGroup.sid -Destination $DstGroup.DistinguishedName -Rights $abuse
        Write-Host "BadACL $abuse $ngroup to $mgroup"
    }

    foreach ($abuse in $Global:BadACL) {
        $hgroup = VulnAD-GetRandom -InputList $Global:HighGroups
        $mgroup = VulnAD-GetRandom -InputList $Global:MidGroups
        $DstGroup = Get-ADGroup -Identity $hgroup
        $SrcGroup = Get-ADGroup -Identity $mgroup
        VulnAD-AddACL -Source $SrcGroup.sid -Destination $DstGroup.DistinguishedName -Rights $abuse
        Write-Host "BadACL $abuse $mgroup to $hgroup"
    }

    for ($i=1; $i -le (Get-Random -Maximum 25); $i++) {
        $abuse = VulnAD-GetRandom -InputList $Global:BadACL
        $randomuser = VulnAD-GetRandom -InputList $Global:CreatedUsers
        $randomgroup = VulnAD-GetRandom -InputList $Global:AllObjects
        if ((Get-Random -Maximum 2)) {
            $Dstobj = Get-ADUser -Identity $randomuser
            $Srcobj = Get-ADGroup -Identity $randomgroup
        } else {
            $Srcobj = Get-ADUser -Identity $randomuser
            $Dstobj = Get-ADGroup -Identity $randomgroup
        }
        VulnAD-AddACL -Source $Srcobj.sid -Destination $Dstobj.DistinguishedName -Rights $abuse
        Write-Host "BadACL $abuse $randomuser and $randomgroup"
    }
}

function VulnAD-Kerberoasting {
    foreach ($entry in $Global:ServicesAccountsAndSPNs) {
        $svc = $entry.Split(',')[0]
        $spn = $entry.Split(',')[1]
        $password = VulnAD-GetRandom -InputList $Global:BadPasswords

        try {
            New-ADUser -Name $svc -SamAccountName $svc -UserPrincipalName "$svc@$Global:Domain" `
                -ServicePrincipalNames "$svc/$spn.$Global:Domain" `
                -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) `
                -Enabled $true -PasswordNeverExpires $true -PassThru | Out-Null

            Write-Host "Kerberoasting user created: $svc ($spn)"
        } catch {
            Write-Warning "Erro ao criar usuário $svc com SPN $spn"
        }
    }
}

function VulnAD-ASREPRoasting {
    for ($i=1; $i -le (Get-Random -Maximum 6); $i++) {
        $randomuser = VulnAD-GetRandom -InputList $Global:CreatedUsers
        $password = VulnAD-GetRandom -InputList $Global:BadPasswords
        Set-ADAccountPassword -Identity $randomuser -Reset -NewPassword (ConvertTo-SecureString $password -AsPlainText -Force)
        Set-ADAccountControl -Identity $randomuser -DoesNotRequirePreAuth $true
        Write-Host "AS-REPRoasting habilitado: $randomuser"
    }
}

function VulnAD-DnsAdmins {
    for ($i=1; $i -le (Get-Random -Maximum 6); $i++) {
        $randomuser = VulnAD-GetRandom -InputList $Global:CreatedUsers
        Add-ADGroupMember -Identity "DnsAdmins" -Members $randomuser
        Write-Host "DnsAdmins : $randomuser"
    }
    $randomg = VulnAD-GetRandom -InputList $Global:MidGroups
    Add-ADGroupMember -Identity "DnsAdmins" -Members $randomg
    Write-Host "DnsAdmins Nested Group : $randomg"
}

function VulnAD-PwdInObjectDescription {
    for ($i=1; $i -le (Get-Random -Maximum 6); $i++) {
        $randomuser = VulnAD-GetRandom -InputList $Global:CreatedUsers
        $password = VulnAD-GetRandom -InputList $Global:BadPasswords
        Set-ADAccountPassword -Identity $randomuser -Reset -NewPassword (ConvertTo-SecureString $password -AsPlainText -Force)
        Set-ADUser $randomuser -Description "User Password: $password"
        Write-Host "Password in Description : $randomuser"
    }
}

function VulnAD-DefaultPassword {
    for ($i=1; $i -le (Get-Random -Maximum 5); $i++) {
        $randomuser = VulnAD-GetRandom -InputList $Global:CreatedUsers
        $password = "Changeme123!"
        Set-ADAccountPassword -Identity $randomuser -Reset -NewPassword (ConvertTo-SecureString $password -AsPlainText -Force)
        Set-ADUser $randomuser -Description "New User ,DefaultPassword"
        Set-ADUser $randomuser -ChangePasswordAtLogon $true
        Write-Host "Default Password : $randomuser"
    }
}

function VulnAD-PasswordSpraying {
    $same_password = "ncc1701"
    for ($i=1; $i -le (Get-Random -Maximum 12); $i++) {
        $randomuser = VulnAD-GetRandom -InputList $Global:CreatedUsers
        Set-ADAccountPassword -Identity $randomuser -Reset -NewPassword (ConvertTo-SecureString $same_password -AsPlainText -Force)
        Set-ADUser $randomuser -Description "Shared User"
        Write-Host "Password Spraying : $randomuser"
    }
}

function VulnAD-DCSync {
    for ($i=1; $i -le (Get-Random -Maximum 6); $i++) {
        $ADObject = [ADSI]("LDAP://" + (Get-ADDomain $Global:Domain).DistinguishedName)
        $randomuser = VulnAD-GetRandom -InputList $Global:CreatedUsers
        $sid = (Get-ADUser -Identity $randomuser).SID

        $guids = @(
            "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
            "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
            "89e95b76-444d-4c62-991a-0facbeda640c",
            "1131f6ae-9c07-11d1-f79f-00c04fc2dcd2"
        )

        foreach ($guid in $guids) {
            $objectGuid = New-Object Guid $guid
            $ace = New-Object DirectoryServices.ActiveDirectoryAccessRule($sid, 'ExtendedRight', 'Allow', $objectGuid)
            $ADObject.psbase.ObjectSecurity.AddAccessRule($ace)
        }

        $ADObject.psbase.CommitChanges()
        Set-ADUser $randomuser -Description "Replication Account"
        Write-Host "DCSync : $randomuser"
    }
}

function VulnAD-DisableSMBSigning {
    Set-SmbClientConfiguration -RequireSecuritySignature 0 -EnableSecuritySignature 0 -Confirm:$false -Force
    Write-Host "SMB Signing desabilitado"
}

function Invoke-Vuln {
    VulnAD-BadAcls
    VulnAD-Kerberoasting
    VulnAD-ASREPRoasting
    VulnAD-DnsAdmins
    VulnAD-PwdInObjectDescription
    VulnAD-DefaultPassword
    VulnAD-PasswordSpraying
    VulnAD-DCSync
    VulnAD-DisableSMBSigning
}

Invoke-Vuln
