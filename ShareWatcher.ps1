#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [string]$Config = "$PSScriptRoot\config.json",
    [switch]$Scan,
    [switch]$Watch,
    [switch]$Fix,
    [switch]$Setup
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path $Config)) { Write-Error "Config file not found: $Config"; exit 1 }
$C = Get-Content $Config -Raw | ConvertFrom-Json

$SHARE    = $C.SharePath.TrimEnd('\')
$MAX      = if ($null -ne $C.MaxPathLength)     { [int]$C.MaxPathLength }     else { 256      }
$WARN_REM = if ($null -ne $C.WarnAtRemaining)   { [int]$C.WarnAtRemaining }   else { 30       }
$STALE    = if ($null -ne $C.StaleFileDays)     { [int]$C.StaleFileDays }     else { 180      }
$ARC_NAME = if ($null -ne $C.ArchiveFolderName) { $C.ArchiveFolderName }      else { '_Archive' }
$LOG_DIR  = if ($null -ne $C.LogDirectory)      { $C.LogDirectory }           else { "$PSScriptRoot\Logs" }
$ARC_ROOT = "$SHARE\$ARC_NAME"
$WFILE    = '!PATH_LENGTH_WARNING.txt'
$EXCLUDE  = @($ARC_NAME, 'System Volume Information', '$RECYCLE.BIN') +
            @($C.ExcludeFolders | Where-Object { $_ })

# SIDs that are always skipped during ACL analysis
# S-1-5-18 = SYSTEM, S-1-5-32-544 = Administrators, S-1-1-0 = Everyone
$SKIP_SID_PREFIXES = @('S-1-5-18', 'S-1-5-32-', 'S-1-1-0', 'S-1-5-11', 'S-1-3-')

# Groups to skip (domain admins, etc) - populated from config
$IGNORE_GROUPS = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
@($C.IgnoreGroups | Where-Object { $_ }) | ForEach-Object { $null = $IGNORE_GROUPS.Add($_) }


#==============================================================================
# LOGGING
#==============================================================================

New-Item -ItemType Directory -Path $LOG_DIR -Force -ErrorAction SilentlyContinue | Out-Null
$LOG    = "$LOG_DIR\scan_$(Get-Date -Format 'yyyy-MM-dd').log"
$REPORT = "$LOG_DIR\report_$(Get-Date -Format 'yyyy-MM-dd_HHmm').txt"

function Write-Log {
    param([string]$Msg, [string]$L = 'INFO')
    $line = "[$(Get-Date -Format 'HH:mm:ss')] [$L] $Msg"
    Add-Content -LiteralPath $LOG -Value $line -Encoding UTF8
    $fg = @{ INFO = 'Gray'; OK = 'Green'; WARN = 'Yellow'; ERROR = 'Red' }[$L]
    Write-Host $line -ForegroundColor $fg
}


function Add-LLP ([string]$p) {
    if ($p -match '^\\\\(?!\?)') { return '\\?\UNC\' + $p.Substring(2) }
    if ($p -notmatch '^\\\\\?')  { return '\\?\' + $p }
    return $p
}

function Remove-LLP ([string]$p) {
    if ($p.StartsWith('\\?\UNC\')) { return '\\' + $p.Substring(8) }
    if ($p.StartsWith('\\?\'))     { return $p.Substring(4) }
    return $p
}

function Skip-Sid ([string]$sid) {
    foreach ($prefix in $SKIP_SID_PREFIXES) {
        if ($sid.StartsWith($prefix)) { return $true }
    }
    return $false
}


function Get-AllItems {
    param([string]$Root, [string[]]$Exclude = @())

    $stack   = [Collections.Generic.Stack[string]]::new()
    $results = [Collections.Generic.List[pscustomobject]]::new()
    $stack.Push($Root)

    while ($stack.Count -gt 0) {
        $cur = $stack.Pop()
        $lp  = Add-LLP $cur

        $dirs = @()
        try   { $dirs = [IO.Directory]::GetDirectories($lp) }
        catch [UnauthorizedAccessException] { Write-Log "Access denied: $cur" WARN; continue }
        catch { Write-Log "Error: $($_.Exception.Message) - $cur" ERROR; continue }

        foreach ($ld in $dirs) {
            $d    = Remove-LLP $ld
            $name = [IO.Path]::GetFileName($d)
            if ($name -in $Exclude) { continue }
            $stack.Push($d)
            try {
                $depth = ($d.Substring($Root.Length).Trim('\') -split '\\').Count
                $results.Add([pscustomobject]@{
                    Type  = 'Dir'
                    Path  = $d
                    LPath = $ld
                    Name  = $name
                    Depth = $depth
                    Info  = [IO.DirectoryInfo]::new($ld)
                })
            } catch {}
        }

        $files = @()
        try { $files = [IO.Directory]::GetFiles($lp) }
        catch { Write-Log "Files unavailable: $cur" WARN }

        foreach ($lf in $files) {
            $f    = Remove-LLP $lf
            $name = [IO.Path]::GetFileName($f)
            if ($name -eq $WFILE) { continue }
            try {
                $results.Add([pscustomobject]@{
                    Type  = 'File'
                    Path  = $f
                    LPath = $lf
                    Name  = $name
                    Depth = 0
                    Info  = [IO.FileInfo]::new($lf)
                })
            } catch {}
        }
    }

    Write-Output $results
}

function Build-ADCache {
    Write-Log "Loading Active Directory..." INFO

    $adAvailable = $null -ne (Get-Module -Name ActiveDirectory -ListAvailable)
    if (-not $adAvailable) {
        Write-Log "ActiveDirectory module not found (RSAT not installed)." WARN
        Write-Log "Only orphaned SIDs will be detected (no group analysis)." WARN
        return $null
    }

    Import-Module ActiveDirectory -ErrorAction SilentlyContinue

    # Users: SID -> object
    $users = [Collections.Generic.Dictionary[string,pscustomobject]]::new(
                [StringComparer]::OrdinalIgnoreCase)
    try {
        Get-ADUser -Filter * -Properties SID, DisplayName, SamAccountName, Enabled |
            ForEach-Object {
                $u = [pscustomobject]@{
                    SID        = $_.SID.Value
                    Name       = if ($_.DisplayName) { $_.DisplayName } else { $_.SamAccountName }
                    SamAccount = $_.SamAccountName
                    Enabled    = $_.Enabled
                }
                $users[$_.SID.Value] = $u
            }
        Write-Log "  AD users loaded: $($users.Count)" INFO
    } catch {
        Write-Log "Error loading AD users: $($_.Exception.Message)" ERROR
        return $null
    }

    # Groups: SID -> object + list of member SIDs
    $groups  = [Collections.Generic.Dictionary[string,pscustomobject]]::new(
                  [StringComparer]::OrdinalIgnoreCase)
    $members = [Collections.Generic.Dictionary[string,string[]]]::new(
                  [StringComparer]::OrdinalIgnoreCase)  # GroupSID -> [UserSIDs]

    try {
        $allGroups = @(Get-ADGroup -Filter * -Properties SID, SamAccountName, Name)
        $n = 0
        foreach ($grp in $allGroups) {
            $n++
            if ($n % 50 -eq 0) { Write-Log "  Groups loaded: $n / $($allGroups.Count)" INFO }

            if ($IGNORE_GROUPS.Contains($grp.Name) -or $IGNORE_GROUPS.Contains($grp.SamAccountName)) {
                continue
            }

            $groups[$grp.SID.Value] = [pscustomobject]@{
                SID        = $grp.SID.Value
                Name       = $grp.Name
                SamAccount = $grp.SamAccountName
            }

            $grpMembers = @()
            try {
                $grpMembers = @(Get-ADGroupMember -Identity $grp -Recursive -ErrorAction Stop |
                    Where-Object { $_.objectClass -eq 'user' -and $users.ContainsKey($_.SID.Value) } |
                    ForEach-Object { $_.SID.Value })
            } catch {
                # Some groups are not enumerable (built-in, too large, etc.)
            }
            $members[$grp.SID.Value] = $grpMembers
        }
        Write-Log "  AD groups loaded: $($groups.Count)" INFO
    } catch {
        Write-Log "Error loading AD groups: $($_.Exception.Message)" ERROR
        return $null
    }

    return [pscustomobject]@{ Users = $users; Groups = $groups; Members = $members }
}


function Find-FolderAnomalies {
    param([string]$Path, [string]$LPath, [pscustomobject]$AD)

    $result = [Collections.Generic.List[pscustomobject]]::new()

    $acl = $null
    try   { $acl = [IO.Directory]::GetAccessControl($LPath) }
    catch { return Write-Output $result }

    # Inheritance manually disabled?
    if ($acl.AreAccessRulesProtected) {
        $result.Add([pscustomobject]@{
            Severity = 'Info'
            Type     = 'InheritanceDisabled'
            Folder   = $Path
            Subject  = ''
            Detail   = 'Folder is isolated from parent permissions. Rights are managed independently here.'
        })
    }

    # Walk explicit (non-inherited) ACL entries
    $rules = $acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier])

    $folderGroupSIDs = [Collections.Generic.List[string]]::new()
    $directUserSIDs  = [Collections.Generic.List[string]]::new()
    $aceRights       = @{}   # SID -> FileSystemRights string

    foreach ($rule in $rules) {
        if ($rule.AccessControlType -ne 'Allow') { continue }
        $sid = $rule.IdentityReference.Value
        if (Skip-Sid $sid) { continue }

        $rights = $rule.FileSystemRights.ToString()
        $aceRights[$sid] = $rights

        if ($null -eq $AD) {
            # AD not available - only orphaned SIDs can be checked
            try {
                $null = [Security.Principal.SecurityIdentifier]::new($sid).Translate(
                            [Security.Principal.NTAccount])
            } catch {
                $result.Add([pscustomobject]@{
                    Severity = 'High'
                    Type     = 'OrphanedSID'
                    Folder   = $Path
                    Subject  = $sid
                    Detail   = "Object was deleted from AD, but its SID ($sid) is still present in the folder's permissions"
                })
            }
            continue
        }

        $isUser  = $AD.Users.ContainsKey($sid)
        $isGroup = $AD.Groups.ContainsKey($sid)

        if ($isUser) {
            $directUserSIDs.Add($sid)
            # A disabled account holding any explicit right is itself an anomaly
            if (-not $AD.Users[$sid].Enabled) {
                $result.Add([pscustomobject]@{
                    Severity = 'High'
                    Type     = 'DisabledUserHasAccess'
                    Folder   = $Path
                    Subject  = "$($AD.Users[$sid].Name) [$($AD.Users[$sid].SamAccount)]"
                    Detail   = "Disabled account still holds an explicit ACL entry ($rights)"
                })
            }
        } elseif ($isGroup) {
            $folderGroupSIDs.Add($sid)
            # Group has rights on the folder but currently has zero members
            $grpMembers = $AD.Members[$sid]
            if (-not $grpMembers -or $grpMembers.Count -eq 0) {
                $result.Add([pscustomobject]@{
                    Severity = 'Info'
                    Type     = 'EmptyGroupHasAccess'
                    Folder   = $Path
                    Subject  = $AD.Groups[$sid].Name
                    Detail   = "Group '$($AD.Groups[$sid].Name)' has rights on this folder but has no members at all"
                })
            }
        } else {
            # Neither a known user nor a known group - a deleted AD object
            $result.Add([pscustomobject]@{
                Severity = 'High'
                Type     = 'OrphanedSID'
                Folder   = $Path
                Subject  = $sid
                Detail   = "Object was deleted from AD, but its SID ($sid) is still present in the folder's permissions ($rights)"
            })
        }
    }

    if ($null -eq $AD -or $directUserSIDs.Count -eq 0) {
        return Write-Output $result
    }

    # Work out who SHOULD have access here based on group membership
    $authorizedSIDs = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($grpSID in $folderGroupSIDs) {
        $m = $AD.Members[$grpSID]
        if ($m) { $m | ForEach-Object { $null = $authorizedSIDs.Add($_) } }
    }

    # Check every user with a direct (explicit) ACL entry
    foreach ($sid in $directUserSIDs) {
        $user   = $AD.Users[$sid]
        $rights = $aceRights[$sid]
        $uname  = "$($user.Name) [$($user.SamAccount)]"

        # A write-capable right is more dangerous than read-only
        $isWrite = $rights -match 'Write|Modify|FullControl|Delete|Change'

        if (-not $authorizedSIDs.Contains($sid)) {
            # CRITICAL: the user has a direct ACL entry but does NOT belong to
            # any group that has access to this folder.
            # Classic case: the user was moved from Group1 to Group3, but the
            # direct entry left over on Group1's folder was never removed.
            $result.Add([pscustomobject]@{
                Severity = if ($isWrite) { 'Critical' } else { 'High' }
                Type     = 'UnauthorizedAccess'
                Folder   = $Path
                Subject  = $uname
                Detail   = "User has a direct ACL entry ($rights) but does NOT belong to any group that is granted access to this folder. Likely a leftover after being moved to a different group."
            })
        } else {
            # User already gets access via a group - the direct entry is redundant.
            # That is itself a problem: if the user is later moved to a different
            # group, this direct entry will be left behind and silently keep working.
            $viaGroups = $folderGroupSIDs |
                Where-Object { ($AD.Members[$_]) -and ($AD.Members[$_] -contains $sid) } |
                ForEach-Object { $AD.Groups[$_].Name } |
                Select-Object -First 3
            $result.Add([pscustomobject]@{
                Severity = 'Medium'
                Type     = 'RedundantDirectAccess'
                Folder   = $Path
                Subject  = $uname
                Detail   = "Access is already granted via group(s): $($viaGroups -join ', '). The direct ACL entry is unnecessary - if this user is moved to a different group, the direct entry will remain and the user will keep access."
            })
        }
    }

    return Write-Output $result
}


function Find-UserAnomalies {
    param([pscustomobject]$AD, [pscustomobject[]]$TopDirs)

    $result = [Collections.Generic.List[pscustomobject]]::new()
    if ($null -eq $AD) { return Write-Output $result }

    # Collect groups referenced in the ACLs of top-level folders (depth = 1)
    $topGroupSIDs = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

    foreach ($d in $TopDirs) {
        $acl = $null
        try { $acl = [IO.Directory]::GetAccessControl($d.LPath) }
        catch { continue }

        $acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]) |
            Where-Object { $_.AccessControlType -eq 'Allow' } |
            Where-Object { $AD.Groups.ContainsKey($_.IdentityReference.Value) } |
            ForEach-Object { $null = $topGroupSIDs.Add($_.IdentityReference.Value) }
    }

    if ($topGroupSIDs.Count -eq 0) { return Write-Output $result }

    # Build a map: UserSID -> list of top-level groups they belong to
    $userGroupMap = [Collections.Generic.Dictionary[string,object]]::new(
                       [StringComparer]::OrdinalIgnoreCase)

    foreach ($grpSID in $topGroupSIDs) {
        $grpMembers = $AD.Members[$grpSID]
        if (-not $grpMembers) { continue }
        $grpName = $AD.Groups[$grpSID].Name

        foreach ($userSID in $grpMembers) {
            if (-not $userGroupMap.ContainsKey($userSID)) {
                $userGroupMap[$userSID] = [Collections.Generic.List[string]]::new()
            }
            $userGroupMap[$userSID].Add($grpName)
        }
    }

    foreach ($kv in $userGroupMap.GetEnumerator()) {
        $userSID = $kv.Key
        $grpList = @($kv.Value)
        $user    = $AD.Users[$userSID]
        if (-not $user) { continue }
        $uname = "$($user.Name) [$($user.SamAccount)]"
        
        if ($grpList.Count -gt 1) {
            $result.Add([pscustomobject]@{
                Severity = 'Medium'
                Type     = 'MemberOfMultipleTopGroups'
                Folder   = '(multiple folders)'
                Subject  = $uname
                Detail   = "User belongs to $($grpList.Count) groups granting access to different top-level folders: $($grpList -join ', '). If this user is only supposed to be in one of them, this needs review."
            })
        }

        # A disabled account is still a member of a group with share access
        if (-not $user.Enabled) {
            $result.Add([pscustomobject]@{
                Severity = 'High'
                Type     = 'DisabledUserInActiveGroup'
                Folder   = "(groups: $($grpList -join ', '))"
                Subject  = $uname
                Detail   = "Disabled account is still a member of group(s) with share access, and technically retains access to the share. Should be removed from these groups."
            })
        }
    }

    return Write-Output $result
}

function Get-PathStatus ([string]$Path) {
    $len = $Path.Length
    [pscustomobject]@{
        Path      = $Path
        Length    = $len
        Remaining = $MAX - $len
        Critical  = ($len -ge $MAX)
        Warning   = ($len -ge ($MAX - $WARN_REM))
    }
}

function Write-WarningFile ([string]$Dir, [int]$Remaining) {
    $dst = [IO.Path]::Combine($Dir, $WFILE)

    # When a file is created inside $Dir, the full path becomes
    # "$Dir\filename.ext" - the backslash separator costs 1 character,
    # so the real budget for a file/folder NAME is Remaining minus 1.
    $nameBudget = $Remaining - 1

    $status = if ($Remaining -le 0) {
        "LIMIT EXCEEDED - files here can no longer be opened"
    } elseif ($nameBudget -le 0) {
        "LIMIT EXCEEDED - there is no room left for a file name in this folder"
    } else {
        "Only $nameBudget characters left for a new file or folder NAME (including the extension)"
    }

    $msg = @"
======================================================
 WARNING: PATH LENGTH TO THIS FOLDER IS CRITICAL
======================================================

 $status

 Files and folders with a path longer than $MAX characters
 CANNOT be opened with standard Windows tools.

 What to do:
   1. Keep new file and folder names short (see budget above).
   2. Shorten the name of one of the parent folders.
   3. Move this folder closer to the share's root.
   4. Contact your system administrator.

 Current path ($($Dir.Length) characters):
   $Dir
======================================================
Created automatically: $(Get-Date -Format 'yyyy-MM-dd HH:mm')
"@
    try { [IO.File]::WriteAllText((Add-LLP $dst), $msg, [Text.Encoding]::UTF8) }
    catch { Write-Log "Could not write warning file in $Dir" WARN }
}

function Clear-StaleWarnings ([pscustomobject[]]$Items) {
    @($Items | Where-Object { $_.Type -eq 'File' -and $_.Name -eq $WFILE }) |
        ForEach-Object {
            $d = [IO.Path]::GetDirectoryName($_.Path)
            if (-not (Get-PathStatus $d).Warning) {
                try { [IO.File]::Delete($_.LPath); Write-Log "Removed stale warning: $($_.Path)" INFO }
                catch {}
            }
        }
}

function Find-StaleFiles ([pscustomobject[]]$Items) {
    $cutoff = (Get-Date).AddDays(-$STALE)
    $Items |
        Where-Object { $_.Type -eq 'File' } |
        ForEach-Object {
            $fi = [IO.FileInfo]$_.Info
            $la = $fi.LastAccessTime
            $lw = $fi.LastWriteTime
            if ($la -lt (Get-Date '2000-01-01')) { $la = $lw }
            $last = if ($la -gt $lw) { $la } else { $lw }
            [pscustomobject]@{
                Path     = $_.Path
                LPath    = $_.LPath
                LastUsed = $last
                DaysIdle = [int]((Get-Date) - $last).TotalDays
                SizeMB   = [math]::Round($fi.Length / 1MB, 2)
            }
        } |
        Where-Object { $_.LastUsed -lt $cutoff } |
        Sort-Object DaysIdle -Descending
}

function Move-ToArchive ([string]$FilePath, [string]$LFilePath) {
    if (-not [IO.Directory]::Exists((Add-LLP $ARC_ROOT))) {
        [IO.Directory]::CreateDirectory((Add-LLP $ARC_ROOT)) | Out-Null
    }
    $rel   = $FilePath.Substring($SHARE.Length).TrimStart('\')
    $dest  = [IO.Path]::Combine($ARC_ROOT, $rel)
    $ldir  = Add-LLP ([IO.Path]::GetDirectoryName($dest))
    if (-not [IO.Directory]::Exists($ldir)) { [IO.Directory]::CreateDirectory($ldir) | Out-Null }
    $ldest = Add-LLP $dest
    if ([IO.File]::Exists($ldest)) {
        $ldest = Add-LLP ($dest -replace '(\.[^.]+)$', "_$(Get-Date -Format 'HHmmss')$1")
    }
    [IO.File]::Move($LFilePath, $ldest)
    Write-Log "  Archived: $FilePath" INFO
}


function Send-Alert ([string]$Subject, [string]$Body) {
    if (-not ($C.Email.Enabled -eq $true)) { return }
    try {
        $msg              = [Net.Mail.MailMessage]::new()
        $msg.From         = $C.Email.From
        $msg.Subject      = $Subject
        $msg.Body         = $Body
        $msg.BodyEncoding = [Text.Encoding]::UTF8
        $C.Email.To | ForEach-Object { $msg.To.Add($_) }
        $smtp = [Net.Mail.SmtpClient]::new($C.Email.SmtpServer, [int]$C.Email.Port)
        if ($C.Email.Username) {
            $smtp.Credentials = [Net.NetworkCredential]::new($C.Email.Username, $C.Email.Password)
            $smtp.EnableSsl   = ($C.Email.UseSsl -eq $true)
        }
        $smtp.Send($msg); $msg.Dispose(); $smtp.Dispose()
    } catch { Write-Log "Email error: $($_.Exception.Message)" ERROR }
}


function New-Report {
    param(
        [pscustomobject[]]$PermAnomalies,
        [pscustomobject[]]$PathIssues,
        [pscustomobject[]]$Stale
    )

    $div = '=' * 66
    $sb  = [Text.StringBuilder]::new()

    $null = $sb.AppendLine($div)
    $null = $sb.AppendLine("  ACCESS RIGHTS MONITORING REPORT")
    $null = $sb.AppendLine("  Date  : $(Get-Date -Format 'yyyy-MM-dd HH:mm')")
    $null = $sb.AppendLine("  Share : $SHARE")
    $null = $sb.AppendLine($div)

    #-- Anomaly summary ----------------------------------------------------
    if ($PermAnomalies -and $PermAnomalies.Count -gt 0) {
        $bySev = $PermAnomalies | Group-Object Severity
        $null  = $sb.AppendLine("")
        $null  = $sb.AppendLine("  TOTAL ANOMALIES: $($PermAnomalies.Count)")
        $bySev | Sort-Object Name | ForEach-Object {
            $null = $sb.AppendLine("    $($_.Name.PadRight(15)): $($_.Count)")
        }
    }

    $severityOrder = @('Critical','High','Medium','Info')
    foreach ($sev in $severityOrder) {
        $group = @($PermAnomalies | Where-Object { $_.Severity -eq $sev })
        if ($group.Count -eq 0) { continue }

        $null = $sb.AppendLine("")
        $null = $sb.AppendLine("  [$sev] - $($group.Count) item(s)")
        $null = $sb.AppendLine("  $('-' * 60)")

        $group | Group-Object Type | ForEach-Object {
            $null = $sb.AppendLine("")
            $null = $sb.AppendLine("  * $($_.Name) ($($_.Count))")
            $_.Group | ForEach-Object {
                $null = $sb.AppendLine("    Folder : $($_.Folder)")
                if ($_.Subject) {
                    $null = $sb.AppendLine("    Who    : $($_.Subject)")
                }
                $null = $sb.AppendLine("    Reason : $($_.Detail)")
                $null = $sb.AppendLine("")
            }
        }
    }

    if (-not $PermAnomalies -or $PermAnomalies.Count -eq 0) {
        $null = $sb.AppendLine("")
        $null = $sb.AppendLine("  OK - no access right anomalies found")
    }

    $crit = @($PathIssues | Where-Object { $_.Critical })
    $warn = @($PathIssues | Where-Object { $_.Warning -and -not $_.Critical })

    $null = $sb.AppendLine("")
    $null = $sb.AppendLine("  [ PATH LENGTH  (limit: $MAX characters) ]")
    if ($crit.Count -eq 0 -and $warn.Count -eq 0) {
        $null = $sb.AppendLine("    OK - all paths are within range")
    } else {
        if ($crit.Count -gt 0) {
            $null = $sb.AppendLine("    Limit exceeded: $($crit.Count)")
            $crit | ForEach-Object { $null = $sb.AppendLine("      [$($_.Length) chars] $($_.Path)") }
        }
        if ($warn.Count -gt 0) {
            $null = $sb.AppendLine("    Close to limit: $($warn.Count)")
            $warn | Select-Object -First 30 | ForEach-Object {
                $null = $sb.AppendLine("      [$($_.Remaining) left] $($_.Path)")
            }
            if ($warn.Count -gt 30) { $null = $sb.AppendLine("      ... and $($warn.Count - 30) more") }
        }
    }

    $null = $sb.AppendLine("")
    $null = $sb.AppendLine("  [ UNUSED FILES  (not opened in over $STALE days) ]")
    if (-not $Stale -or $Stale.Count -eq 0) {
        $null = $sb.AppendLine("    OK - no such files found")
    } else {
        $totalMB = [math]::Round(($Stale | Measure-Object SizeMB -Sum).Sum, 1)
        $null = $sb.AppendLine("    Found: $($Stale.Count) file(s), $totalMB MB -> archive: $ARC_ROOT")
        $Stale | Select-Object -First 100 | ForEach-Object {
            $null = $sb.AppendLine("      [$($_.DaysIdle) days, $($_.SizeMB) MB] $($_.Path)")
        }
        if ($Stale.Count -gt 100) { $null = $sb.AppendLine("      ... and $($Stale.Count - 100) more") }
        if ($Fix -and $C.AutoArchive -eq $true) {
            $null = $sb.AppendLine("    Files were moved to the archive (-Fix mode)")
        } else {
            $null = $sb.AppendLine("    To archive: .\ShareWatcher.ps1 -Scan -Fix")
        }
    }

    $null = $sb.AppendLine("")
    $null = $sb.AppendLine($div)

    $text = $sb.ToString()
    [IO.File]::WriteAllText($REPORT, $text, [Text.Encoding]::UTF8)
    Write-Host "`n$text" -ForegroundColor Cyan
    Write-Log "Report: $REPORT" OK

    $critical = @($PermAnomalies | Where-Object { $_.Severity -in 'Critical','High' })
    if ($critical.Count -gt 0 -or $crit.Count -gt 0) {
        Send-Alert "ShareWatcher: $($critical.Count) critical issues $(Get-Date -Format 'yyyy-MM-dd')" $text
    }
}

function Start-Scan {
    Write-Log "====  Starting scan: $SHARE  ====" INFO
    $sw = [Diagnostics.Stopwatch]::StartNew()

    # 1. Load AD
    $AD = Build-ADCache

    # 2. Walk the share
    Write-Log "Walking folder tree..." INFO
    $items = @(Get-AllItems -Root $SHARE -Exclude $EXCLUDE)
    $dirs  = @($items | Where-Object { $_.Type -eq 'Dir'  })
    $files = @($items | Where-Object { $_.Type -eq 'File' })
    Write-Log "Found: $($dirs.Count) folders, $($files.Count) files" INFO

    # 3. Check rights on every folder
    Write-Log "Analyzing access rights..." INFO
    $permAnomalies = [Collections.Generic.List[pscustomobject]]::new()
    $n = 0
    foreach ($d in $dirs) {
        $n++
        if ($n % 200 -eq 0) { Write-Log "  Checked: $n / $($dirs.Count)" INFO }
        @(Find-FolderAnomalies -Path $d.Path -LPath $d.LPath -AD $AD) |
            ForEach-Object { $permAnomalies.Add($_) }
    }

    # 4. User-level anomalies (members of multiple groups, etc.)
    Write-Log "Analyzing users..." INFO
    $topDirs = @($dirs | Where-Object { $_.Depth -eq 1 })
    @(Find-UserAnomalies -AD $AD -TopDirs $topDirs) |
        ForEach-Object { $permAnomalies.Add($_) }

    Write-Log "Access anomalies found: $($permAnomalies.Count)" INFO

    # 5. Path length
    Write-Log "Checking path lengths..." INFO
    $pathIssues = @($items | ForEach-Object { Get-PathStatus $_.Path } | Where-Object { $_.Warning })

    $dirSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $dirs | ForEach-Object { $null = $dirSet.Add($_.Path) }

    $warned = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($pi in $pathIssues) {
        $d = if ($dirSet.Contains($pi.Path)) { $pi.Path } else { [IO.Path]::GetDirectoryName($pi.Path) }
        if ($warned.Add($d)) { Write-WarningFile -Dir $d -Remaining $pi.Remaining }
    }
    Clear-StaleWarnings -Items $items

    # 6. Stale files
    Write-Log "Looking for unused files (> $STALE days)..." INFO
    $stale = @(Find-StaleFiles -Items $items)

    if ($Fix -and $C.AutoArchive -eq $true) {
        foreach ($sf in $stale) {
            try   { Move-ToArchive -FilePath $sf.Path -LFilePath $sf.LPath }
            catch { Write-Log "Archiving error: $($_.Exception.Message)" ERROR }
        }
    }

    $sw.Stop()
    New-Report -PermAnomalies $permAnomalies.ToArray() -PathIssues $pathIssues -Stale $stale
    Write-Log "====  Done in $([int]$sw.Elapsed.TotalMinutes) min.  ====" OK
}


function Get-FileOwner ([string]$LongPath, [bool]$IsDir) {
    try {
        $sec = if ($IsDir) { [IO.Directory]::GetAccessControl($LongPath) }
               else        { [IO.File]::GetAccessControl($LongPath) }
        $owner = $sec.GetOwner([Security.Principal.NTAccount]).Value
        if ($owner -match '\\') {
            return ($owner -split '\\')[-1]
        }
        return $owner
    } catch {
        return $null
    }
}

function Find-UserComputer ([string]$SamAccountName) {
    if (-not $C.UserNotifications) { return $null }

    # 1. Manual lookup table - fast path, checked first
    $map = $C.UserNotifications.ComputerMap
    if ($map) {
        $entry = $map.PSObject.Properties | Where-Object { $_.Name -ieq $SamAccountName }
        if ($entry) { return $entry.Value }
    }

    # 2. Optional live discovery across domain computers
    if ($C.UserNotifications.AutoDiscoverComputer -ne $true) { return $null }

    $adAvailable = $null -ne (Get-Module -Name ActiveDirectory -ListAvailable)
    if (-not $adAvailable) { return $null }

    $timeout = if ($C.UserNotifications.DiscoveryTimeoutSeconds) {
        [int]$C.UserNotifications.DiscoveryTimeoutSeconds
    } else { 3 }

    try {
        $computers = @(Get-ADComputer -Filter * -Properties Name | Select-Object -ExpandProperty Name)
    } catch { return $null }

    foreach ($comp in $computers) {
        try {
            $cs = Get-CimInstance -ComputerName $comp -ClassName Win32_ComputerSystem `
                    -ErrorAction Stop -OperationTimeoutSec $timeout
            if ($cs.UserName -and ($cs.UserName -match '\\') -and
                (($cs.UserName -split '\\')[-1] -ieq $SamAccountName)) {
                return $comp
            }
        } catch { continue }
    }
    return $null
}

function Send-UserPopup {
    param([string]$SamAccountName, [string]$ComputerName, [string]$Message)

    $title = if ($C.UserNotifications.MessageTitle) { $C.UserNotifications.MessageTitle } `
             else { 'ShareWatcher' }

    $fullMsg = "$title`r`n`r`n$Message"

    try {
        $msgArgs = @("/SERVER:$ComputerName", '/TIME:60', $SamAccountName, $fullMsg)
        $out = & msg.exe @msgArgs 2>&1
        Write-Log "Popup sent to $SamAccountName on $ComputerName" OK
    } catch {
        Write-Log "Could not deliver popup to $SamAccountName on $ComputerName : $($_.Exception.Message)" WARN
    }
}

function Send-PathWarningPopup {
    param([string]$FullPath, [bool]$IsDir, [int]$Remaining, [int]$NameBudget)

    if (-not ($C.UserNotifications.Enabled -eq $true)) { return }

    $longPath = Add-LLP $FullPath
    $owner    = Get-FileOwner -LongPath $longPath -IsDir $IsDir
    if (-not $owner) {
        Write-Log "Could not determine the owner of $FullPath - skipping popup" WARN
        return
    }

    $computer = Find-UserComputer -SamAccountName $owner
    if (-not $computer) {
        Write-Log "Could not find a computer for user '$owner' - skipping popup (text warning file was still created)" WARN
        return
    }

    $budgetLine = if ($NameBudget -le 0) {
        "There is no room left for a file name in this folder."
    } else {
        "You have about $NameBudget characters left for a new file or folder name (including the extension)."
    }

    $message = "The folder you just created is close to Windows' path length limit ($MAX characters).`r`n$budgetLine`r`nUse shorter names, or files inside this folder may fail to open.`r`n`r`nPath: $FullPath"

    # Dispatched as a background job so a slow or unreachable computer
    # never blocks the real-time monitoring loop from seeing new events.
    Start-Job -ScriptBlock {
        param($sam, $comp, $msg, $title)
        try {
            $fullMsg = "$title`r`n`r`n$msg"
            & msg.exe "/SERVER:$comp" '/TIME:60' $sam $fullMsg 2>&1 | Out-Null
        } catch {}
    } -ArgumentList $owner, $computer, $message, $(
        if ($C.UserNotifications.MessageTitle) { $C.UserNotifications.MessageTitle } else { 'ShareWatcher' }
    ) | Out-Null

    Write-Log "Popup dispatched to $owner @ $computer for $FullPath" INFO
}

function Start-Watch {
    Write-Log "====  Watching: $SHARE  ====" INFO
    Write-Log "Press Ctrl+C to stop." INFO

    if ($C.UserNotifications -and $C.UserNotifications.Enabled -eq $true) {
        Write-Log "User popup notifications: ENABLED (delivered via msg.exe)" OK
    } else {
        Write-Log "User popup notifications: DISABLED - set UserNotifications.Enabled to true in config.json to turn on" WARN
    }

    $watcher = [IO.FileSystemWatcher]::new($SHARE)
    $watcher.IncludeSubdirectories = $true
    $watcher.EnableRaisingEvents   = $false
    $watcher.NotifyFilter = [IO.NotifyFilters]::FileName -bor [IO.NotifyFilters]::DirectoryName

    try {
        while ($true) {
            $ch = $watcher.WaitForChanged([IO.WatcherChangeTypes]::Created, 1500)
            if ($ch.TimedOut) { continue }
            $name = [IO.Path]::GetFileName($ch.Name)
            if ($name -like '*WARNING*') { continue }
            $full = [IO.Path]::Combine($SHARE, $ch.Name)
            $ps   = Get-PathStatus $full
            if (-not $ps.Warning) { continue }
            $isDir = try { [IO.Directory]::Exists((Add-LLP $full)) } catch { $false }
            $dir   = if ($isDir) { $full } else { [IO.Path]::GetDirectoryName($full) }
            Write-Log "Object created: $($ps.Remaining) chars left until limit - $full" WARN
            Write-WarningFile -Dir $dir -Remaining $ps.Remaining
            Send-PathWarningPopup -FullPath $full -IsDir $isDir -Remaining $ps.Remaining -NameBudget ($ps.Remaining - 1)
        }
    } finally {
        $watcher.Dispose()
        Write-Log "Monitoring stopped." INFO
    }

}

function Install-ScheduledTask {
    $args_str = "-NonInteractive -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Scan"
    if ($C.AutoArchive -eq $true) { $args_str += ' -Fix' }

    $action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $args_str
    $trigger   = New-ScheduledTaskTrigger -Daily -At '02:00AM'
    $settings  = New-ScheduledTaskSettingsSet -ExecutionTimeLimit '06:00:00' `
                     -RunOnlyIfNetworkAvailable -StartWhenAvailable -MultipleInstances IgnoreNew
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest

    Register-ScheduledTask -TaskName 'ShareWatcher' -Action $action -Trigger $trigger `
        -Settings $settings -Principal $principal -Force `
        -Description 'Monitors AD-based access rights, path length and stale files on a network share' | Out-Null

    Write-Log "Task 'ShareWatcher' registered (daily at 02:00)" OK
}

function Show-Help {
    Write-Host @'

ShareWatcher - network share monitor

GETTING STARTED:

  1. Copy ShareWatcher.ps1 and config.json to the server
  2. Set the share path in config.json ("SharePath")
  3. Run: .\ShareWatcher.ps1 -Scan

COMMANDS:

  -Scan           Full scan:
                  - Compares real folder ACLs against current AD group membership
                  - Finds direct user rights that bypass group membership
                  - Finds deleted/disabled users still present in ACLs
                  - Finds users who belong to more than one "primary" group
                  - Checks path length
                  - Finds stale files

  -Scan -Fix      Same as above, plus moving stale files into the archive
                  (if AutoArchive: true in config.json)

  -Watch          Real-time monitoring: warns about path length as files
                  and folders are created. If UserNotifications.Enabled is
                  true in config.json, also pops a live message window on
                  the screen of the user who created the problematic item.

  -Setup          Register a daily scheduled task in Windows (runs at 02:00)

  -Config <path>  Use a different configuration file

'@
}

try {
    switch ($true) {
        $Setup { Install-ScheduledTask; break }
        $Scan  { Start-Scan;           break }
        $Watch { Start-Watch;          break }
        default { Show-Help }
    }
} catch {
    Write-Log "FATAL ERROR: $($_.Exception.Message)" ERROR
    Write-Log $_.ScriptStackTrace ERROR
    exit 1
}
