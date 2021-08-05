$pathList = @("$env:ProgramFiles",
              "$env:ALLUSERSPROFILE",
              "$env:CommonProgramFiles",
              "${env:CommonProgramFiles(x86)}",
              "$env:USERPROFILE\AppData\Local")




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
                        if (($group.FileSystemRights -band $right) -eq $right ) {
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
    $lookupGroupSIDs = @("S-1-5-32-545", "S-1-1-0", "S-1-5-11", (Get-LocalUser -Name $env:UserName).SID.value)  # Пользователи Well-known SID + current user

    $Result = @{}
    Get-ChildItem -Path $Path -File -Recurse -ErrorAction SilentlyContinue | foreach {
        
        try {
            $tmp = _checkACL -acls $_.GetAccessControl().Access -aclref $lookupRights -sidref $lookupGroupSIDs

            if ($tmp.count -ne 0) {
                $Result.Add($_.FullName,  $tmp)
            }
        } catch {
            Write-Host ("Error with path '{0}'. Error: {1}" -f $_.FullName, $Error[0].Exception.Message)
        }

        Write-Verbose ("checking {0} accessable {1}" -f $_.FullName, $tmp.count)
    }
    return $Result
}

$r = @{}
$pathList | foreach { 
    $tmp = CheckACLforPath -Path $_ -Verbose
    $r += ($tmp ) 
}
$r.keys | sort