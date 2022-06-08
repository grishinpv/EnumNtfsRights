$pathList = @("HKCU:\SOFTWARE",
              "HKLM:\SOFTWARE",
              "$env:ProgramFiles",
              "$env:ALLUSERSPROFILE",
              "$env:CommonProgramFiles",
              "${env:CommonProgramFiles(x86)}",
              "$env:USERPROFILE\AppData\Local")

Function ConvertTo-NTAccount
{
  <#
      .SYNOPSIS
      Convert a string containing either the numeric SID or a symbolic
      name, or a SID object to an NTAccount object.
  #>
    param(
        ## Value to be converted. Accepts a string with either a numeric
        ## SID or a symbolic name, or a SID object, or an NTAccount object
        ## (in this case just returns as-is).
        [Parameter(Mandatory=$true, ValueFromPipeline = $true)]
        $From
    )

    if ($From -is [System.Security.Principal.NTAccount]) {
        return $From
    }
    if ($From -is [System.Security.Principal.SecurityIdentifier]) {
        $fResult = $From.Translate([System.Security.Principal.NTAccount])
        return $fResult
    }
    if (!($From -is [string])) {
        Throw "Don't know how to convert an object of type '$($From.GetType())' to an NTAccount"
    }
    try {
        # Try the symbolic format first.
        # For the symbolic format, translate twice, to make sure that
        # the value is valid.
        
        #Write-VerboseEx ("[{0}] sid_1 ->" -f $MyInvocation.MyCommand)
        $sid = new-object System.Security.Principal.SecurityIdentifier($From)
        #Write-VerboseEx ("[{0}] sid_1 <-" -f $MyInvocation.MyCommand)
        #Write-VerboseEx ("[{0}] return translate" -f $MyInvocation.MyCommand)
        $fResult = $sid.Translate([System.Security.Principal.NTAccount])
        return $fResult

    } catch {
        
        #Write-VerboseEx ("[{0}] acc ->" -f $MyInvocation.MyCommand)
        $acc = new-object System.Security.Principal.NTAccount($From)
        #Write-VerboseEx ("[{0}] acc <-" -f $MyInvocation.MyCommand)
        #Write-VerboseEx ("[{0}] sid ->" -f $MyInvocation.MyCommand)
        $sid = $acc.Translate([System.Security.Principal.SecurityIdentifier])
        #Write-VerboseEx ("[{0}] sid <-" -f $MyInvocation.MyCommand)
        #Write-VerboseEx ("[{0}] return translate" -f $MyInvocation.MyCommand)
        $fResult = $sid.Translate([System.Security.Principal.NTAccount])
        return $fResult        
    }
}

Function GetGroupsForUser{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)] 
        $username
    )

    $fResult = @()

    # get domain groups
    try {
        $ad_user = Get-ADUser $username
        $ad_ntaccount = ConvertTo-NTAccount($ad_user.SID)
    } catch {
        return 
    }
    $dn = $ad_user.DistinguishedName
    $domain_groups = Get-ADGroup -LDAPFilter ("(member:1.2.840.113556.1.4.1941:={0})" -f $dn)
    $domain_gorups_sids = $domain_groups | select @{ N = 'sid';  Expression = {$_.SID.Value}} | select -ExpandProperty sid
    #append well known groups
    Get-AdPrincipalGroupMembership $username | ForEach-Object {
         if ($_.SID.Value -notin $domain_gorups_sids) {
            $domain_groups+=$_
            $domain_gorups_sids+=$_.SID.Value
         }
    }

    #local groups
    Get-LocalGroup | ForEach-Object {
        $gr = $_
        Get-LocalGroupMember $gr | ForEach-Object {
            if ($_.Name.tolower() -eq $ad_ntaccount.value.tolower()) {
                $fResult+=$gr 
                continue
            }

            if ($_.ObjectClass.tolower() -in @("group", "группа") -and $_.PrincipalSource -eq "ActiveDirectory") {
                
                if ($_.SID.Value -in $domain_gorups_sids) {
                    $fResult+=$gr
                }
            }


        }
        
    }

    $fResult += $domain_groups
    return $fResult
}


function _checkACL {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)] 
        $acls,

        [Parameter(Mandatory=$true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)] 
        $aclref, 

        [Parameter(Mandatory=$true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)] 
        $sidref
    )

    $fResult = @()
    

    $acls | where { $_.AccessControlType -eq "Allow" } | group IdentityReference | foreach {
        $MatchedAccess = @()

        $identity = $_.group[0].IdentityReference

        foreach ($group in $_.group) {
            try {
                if ($group.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -in $sidref)  {

                    foreach ($right in $aclref) {
                        if ($item.GetType().Name -eq "RegistryKey") {
                            $itemACL = $group.RegistryRights   
                            if ($right -eq [System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes) {
                                continue # registry does not have this right
                            }
                        } else {
                            $itemACL = $group.FileSystemRights             
                        }
                        if (($itemACL -band $right) -eq $right ) {
                            $MatchedAccess += $right.ToString()
           
                        } 
                    }

                
                }
            } catch {
                Write-Debug "skip"
            }
        }

        if ($MatchedAccess.count -ne 0) {
            $fResult+= @{$identity = $MatchedAccess}
        }
    }

    return $fResult

}




Function CheckACLforPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)] 
        $Path
    )

    $lookupRights = @([System.Security.AccessControl.FileSystemRights]::AppendData, 
                  [System.Security.AccessControl.FileSystemRights]::CreateFiles, 
                  [System.Security.AccessControl.FileSystemRights]::Delete, 
                  [System.Security.AccessControl.FileSystemRights]::FullControl,
                  [System.Security.AccessControl.FileSystemRights]::Modify,
                  [System.Security.AccessControl.FileSystemRights]::Write,
                  [System.Security.AccessControl.FileSystemRights]::WriteAttributes, 
                  [System.Security.AccessControl.FileSystemRights]::WriteData, 
                  [System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes)
    $lookupGroupSIDs = @("S-1-5-32-545", "S-1-1-0", "S-1-5-11")  # Пользователи Well-known SID 
    $lookupGroupSIDs += GetGroupsForUser $env:UserName | select @{ N = 'sid';  Expression = {$_.SID.Value}} | select -ExpandProperty sid   # + current user groups

    $Result = @{}
    Get-ChildItem -Path $Path -Recurse -ErrorAction SilentlyContinue | foreach {
        $item = $_
        $tmp = $null

        try {
            if ($item.GetType().Name -eq "RegistryKey") {
                $itemPath = $item.Name
            } else {
                $itemPath = $item.FullName             
            }

            $tmp = _checkACL -acls $item.GetAccessControl().Access -aclref $lookupRights -sidref $lookupGroupSIDs

            if ($tmp.count -ne 0) {        
                $Result.Add($itemPath,  $tmp)
            
            }
        } catch {
            Write-Host ("Error with path '{0}'. Error: {1}" -f $_.FullName, $Error[0].Exception.Message)
        }
        

        

        Write-Verbose ("checking {0} accessable {1}" -f $itemPath, $tmp.count)
    }
    return $Result
}

$r = @{}
$pathList | foreach { 
    $tmp = CheckACLforPath -Path $_ -Verbose
    $r += ($tmp ) 
}

$r.keys | sort
