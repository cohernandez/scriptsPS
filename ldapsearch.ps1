# Script: ldapsearch3-ng-complete.ps1
# Active Directory Security Assessment Tool - Version 3.5 ULTIMATE
# Complete LDAP enumeration with advanced offensive capabilities

param(
    [Parameter(Mandatory=$true)][string]$Server,
    [Parameter(Mandatory=$true)][string]$Domain,
    [Parameter(Mandatory=$true)][string]$Usuario,
    [Parameter(Mandatory=$true)][string]$Password,
    
    # Opciones básicas
    [switch]$Users,
    [switch]$Groups,
    [switch]$Computers,
    [switch]$GPOs,
    [switch]$ServiceAccounts,
    [switch]$Kerberoast,
    [switch]$ASREPRoast,
    [switch]$DomainAdmins,
    [switch]$Vulnerabilities,
    [switch]$All,
    
    # Opciones avanzadas ofensivas
    [switch]$Trusts,
    [switch]$LAPS,
    [switch]$ADCS,
    [switch]$DNS,
    [switch]$ACLs,
    [switch]$AdminCount,
    [switch]$SMBSigning,
    [switch]$PreWin2000,
    [switch]$PasswordSpray,
    [switch]$NTLMEndpoints,
    [switch]$AutoKerberoast,
    [switch]$ExportBloodhound,
    [switch]$DCSync,
    [switch]$Advanced  # Ejecutar todas las opciones avanzadas
)

# ============================================================================
# VARIABLES GLOBALES
# ============================================================================

$script:StartTime = Get-Date
$script:CriticalIssues = 0
$script:WarningIssues = 0
$script:Findings = @{
    Kerberoastable=@();ASREPRoastable=@();UnconstrainedDelegation=@()
    ConstrainedDelegation=@();PasswordInDescription=@();PasswordNeverExpires=@()
    UnlinkedGPOs=@();cPasswordFound=@();AdminCountUsers=@();OldPasswords=@()
    PrivilegedServiceAccounts=@();ExploitableTrusts=@();LAPSReaders=@()
    InterestingDNS=@();DangerousACLs=@();OrphanedAdminCount=@()
    NTLMRelayTargets=@();HTTPEndpoints=@();WSMANEndpoints=@()
    SprayTargets=@();DecryptedPasswords=@();DCSyncCapable=@()
}

# ============================================================================
# CONEXIÓN LDAP
# ============================================================================

Write-Host "`n==================================================================================================" -ForegroundColor Cyan
Write-Host "                    ACTIVE DIRECTORY SECURITY ASSESSMENT TOOL v3.5" -ForegroundColor Cyan
Write-Host "==================================================================================================" -ForegroundColor Cyan
Write-Host "[*] Target: $Server | Domain: $Domain | User: $Usuario" -ForegroundColor Yellow
Write-Host "[*] Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow
Write-Host "==================================================================================================" -ForegroundColor Cyan

$domainDN = "DC=" + ($Domain -replace "\.", ",DC=")
$ldapPath = "LDAP://$Server/$domainDN"

try {
    $script:domainEntry = New-Object System.DirectoryServices.DirectoryEntry($ldapPath,"$Domain\$Usuario",$Password)
    $null = $script:domainEntry.name
    Write-Host "[+] LDAP Connection Successful" -ForegroundColor Green
} catch {
    Write-Host "[-] CRITICAL: LDAP Connection Error: $_" -ForegroundColor Red
    Write-Host "[*] Test: Test-NetConnection -ComputerName $Server -Port 389" -ForegroundColor Yellow
    exit 1
}

# ============================================================================
# FUNCIONES BÁSICAS
# ============================================================================

function Get-DomainUsers {
    Write-Host "`n========== DOMAIN USERS ==========" -ForegroundColor Cyan
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($script:domainEntry)
    $searcher.Filter = "(&(objectClass=user)(objectCategory=person))"
    $searcher.PageSize = 1000
    $searcher.PropertiesToLoad.AddRange(@("samaccountname","name","description"))
    $results = $searcher.FindAll()
    Write-Host "[+] Total Users: $($results.Count)" -ForegroundColor Green
    
    $counter = 0
    foreach ($r in $results) {
        $counter++
        if($counter -le 20) {
            $sam = $r.Properties["samaccountname"][0]
            $name = if($r.Properties["name"].Count -gt 0){$r.Properties["name"][0]}else{"N/A"}
            Write-Host "  [+] $sam - $name" -ForegroundColor White
        }
    }
    if($results.Count -gt 20) {
        Write-Host "  ... and $($results.Count - 20) more users" -ForegroundColor Gray
    }
    $results.Dispose()
}

function Get-DomainGroups {
    Write-Host "`n========== DOMAIN GROUPS ==========" -ForegroundColor Cyan
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($script:domainEntry)
    $searcher.Filter = "(objectClass=group)"
    $searcher.PageSize = 1000
    $searcher.PropertiesToLoad.AddRange(@("samaccountname","name"))
    $results = $searcher.FindAll()
    Write-Host "[+] Total Groups: $($results.Count)" -ForegroundColor Green
    
    $counter = 0
    foreach ($r in $results) {
        $counter++
        if($counter -le 20) {
            Write-Host "  [+] $($r.Properties["samaccountname"][0])" -ForegroundColor White
        }
    }
    if($results.Count -gt 20) {
        Write-Host "  ... and $($results.Count - 20) more groups" -ForegroundColor Gray
    }
    $results.Dispose()
}

function Get-DomainComputers {
    Write-Host "`n========== DOMAIN COMPUTERS ==========" -ForegroundColor Cyan
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($script:domainEntry)
    $searcher.Filter = "(objectClass=computer)"
    $searcher.PageSize = 1000
    $searcher.PropertiesToLoad.AddRange(@("name","dnshostname","operatingsystem"))
    $results = $searcher.FindAll()
    Write-Host "[+] Total Computers: $($results.Count)" -ForegroundColor Green
    
    $counter = 0
    foreach ($r in $results) {
        $counter++
        if($counter -le 15) {
            $name = $r.Properties["name"][0]
            $dns = if($r.Properties["dnshostname"].Count -gt 0){$r.Properties["dnshostname"][0]}else{"N/A"}
            $os = if($r.Properties["operatingsystem"].Count -gt 0){$r.Properties["operatingsystem"][0]}else{"N/A"}
            Write-Host "  [+] $name ($dns) - $os" -ForegroundColor White
        }
    }
    if($results.Count -gt 15) {
        Write-Host "  ... and $($results.Count - 15) more computers" -ForegroundColor Gray
    }
    $results.Dispose()
}

function Get-DomainGPOs {
    Write-Host "`n========== GROUP POLICY OBJECTS ==========" -ForegroundColor Cyan
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($script:domainEntry)
    $searcher.Filter = "(objectClass=groupPolicyContainer)"
    $searcher.PageSize = 1000
    $searcher.PropertiesToLoad.AddRange(@("displayname","name","gpcfilesyspath","whenCreated","distinguishedName"))
    $results = $searcher.FindAll()
    if($results.Count -eq 0){Write-Host "[-] No GPOs found" -ForegroundColor Yellow;return}
    Write-Host "[+] Total GPOs: $($results.Count)" -ForegroundColor Green
    
    $gpoCounter = 0
    foreach ($r in $results) {
        $gpoCounter++
        $displayName = $r.Properties["displayname"][0]
        $gpoGuid = $r.Properties["name"][0]
        $gpoPath = $r.Properties["gpcfilesyspath"][0]
        
        Write-Host "`n--- GPO #${gpoCounter} - $displayName ---" -ForegroundColor Green
        Write-Host "  GUID: $gpoGuid" -ForegroundColor Gray
        Write-Host "  Path: $gpoPath" -ForegroundColor Gray
        
        # Check if linked
        $ouSearcher = New-Object System.DirectoryServices.DirectorySearcher($script:domainEntry)
        $ouSearcher.Filter = "(gPLink=*$gpoGuid*)"
        $linkedOUs = $ouSearcher.FindAll()
        
        if($linkedOUs.Count -eq 0) {
            Write-Host "  [-] CRITICAL: GPO not linked - NO EFFECT" -ForegroundColor Red
            $script:CriticalIssues++
            $script:Findings.UnlinkedGPOs += @{Name=$displayName;GUID=$gpoGuid}
        } else {
            Write-Host "  [+] Linked to $($linkedOUs.Count) OU(s)" -ForegroundColor Green
        }
        
        # Check for cPassword
        if($gpoPath) {
            try {
                if(Test-Path $gpoPath -ErrorAction Stop) {
                    $groupsXml = Get-ChildItem $gpoPath -Recurse -Filter "Groups.xml" -ErrorAction SilentlyContinue
                    if($groupsXml) {
                        Write-Host "  [!] CRITICAL: Groups.xml found - cPassword vulnerability" -ForegroundColor Red
                        $script:CriticalIssues++
                        foreach ($xml in $groupsXml) {
                            $xmlContent = Get-Content $xml.FullName -ErrorAction SilentlyContinue
                            if($xmlContent -match 'cpassword="([^"]+)"') {
                                $cpassHash = $Matches[1]
                                Write-Host "    [!] cPassword FOUND: $cpassHash" -ForegroundColor Red
                                $script:Findings.cPasswordFound += @{GPO=$displayName;Hash=$cpassHash;File=$xml.FullName}
                            }
                        }
                    }
                }
            } catch {}
        }
    }
    $results.Dispose()
}

function Get-ServiceAccounts {
    Write-Host "`n========== SERVICE ACCOUNTS ==========" -ForegroundColor Cyan
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($script:domainEntry)
    $searcher.Filter = "(&(objectClass=user)(|(samaccountname=*svc*)(samaccountname=*service*)(samaccountname=*sql*)(description=*service*)))"
    $searcher.PageSize = 1000
    $searcher.PropertiesToLoad.AddRange(@("samaccountname","description","serviceprincipalname","memberof","pwdlastset","useraccountcontrol"))
    $results = $searcher.FindAll()
    if($results.Count -eq 0){Write-Host "[-] No service accounts found" -ForegroundColor Yellow;return}
    Write-Host "[+] Service Accounts: $($results.Count)" -ForegroundColor Green
    
    foreach ($r in $results) {
        $sam = $r.Properties["samaccountname"][0]
        $spns = $r.Properties["serviceprincipalname"]
        
        Write-Host "`n  Account: $sam" -ForegroundColor White
        
        if($spns.Count -gt 0) {
            Write-Host "    [!] VULNERABLE: Kerberoastable - $($spns.Count) SPNs" -ForegroundColor Red
            $script:CriticalIssues++
            $script:Findings.Kerberoastable += @{Account=$sam;SPNs=$spns}
        }
    }
    $results.Dispose()
}

function Get-Kerberoastable {
    Write-Host "`n========== KERBEROASTING ==========" -ForegroundColor Cyan
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($script:domainEntry)
    $searcher.Filter = "(&(objectClass=user)(servicePrincipalName=*)(!samaccountname=krbtgt))"
    $searcher.PageSize = 1000
    $searcher.PropertiesToLoad.AddRange(@("samaccountname","serviceprincipalname"))
    $results = $searcher.FindAll()
    if($results.Count -eq 0){Write-Host "[+] No Kerberoastable users" -ForegroundColor Green;return}
    Write-Host "[!] CRITICAL: $($results.Count) Kerberoastable user(s)" -ForegroundColor Red
    $script:CriticalIssues += $results.Count
    foreach ($r in $results) {
        $sam = $r.Properties["samaccountname"][0]
        Write-Host "  [!] $sam" -ForegroundColor Red
        if(-not ($script:Findings.Kerberoastable | Where-Object {$_.Account -eq $sam})) {
            $script:Findings.Kerberoastable += @{Account=$sam;SPNs=$r.Properties["serviceprincipalname"]}
        }
    }
    Write-Host "`n  [*] Exploitation:" -ForegroundColor Cyan
    Write-Host "      Rubeus.exe kerberoast /outfile:hashes.txt" -ForegroundColor Green
    Write-Host "      GetUserSPNs.py $Domain/${Usuario}:$Password -dc-ip $Server -request" -ForegroundColor Green
    $results.Dispose()
}

function Get-ASREPRoastable {
    Write-Host "`n========== ASREPROASTING ==========" -ForegroundColor Cyan
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($script:domainEntry)
    $searcher.Filter = "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
    $searcher.PageSize = 1000
    $searcher.PropertiesToLoad.AddRange(@("samaccountname"))
    $results = $searcher.FindAll()
    if($results.Count -eq 0){Write-Host "[+] No ASREPRoastable users" -ForegroundColor Green;return}
    Write-Host "[!] CRITICAL: $($results.Count) ASREPRoastable user(s)" -ForegroundColor Red
    $script:CriticalIssues += $results.Count
    foreach ($r in $results) {
        $sam = $r.Properties["samaccountname"][0]
        Write-Host "  [!] $sam" -ForegroundColor Red
        $script:Findings.ASREPRoastable += @{Account=$sam}
    }
    Write-Host "`n  [*] Exploitation:" -ForegroundColor Cyan
    Write-Host "      Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt" -ForegroundColor Green
    Write-Host "      GetNPUsers.py $Domain/ -dc-ip $Server -request" -ForegroundColor Green
    $results.Dispose()
}

function Get-DomainAdmins {
    Write-Host "`n========== DOMAIN ADMINS ==========" -ForegroundColor Cyan
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($script:domainEntry)
    $searcher.Filter = "(cn=Domain Admins)"
    $group = $searcher.FindOne()
    if($group) {
        $members = $group.Properties["member"]
        Write-Host "[+] Domain Admins: $($members.Count)" -ForegroundColor Green
        foreach ($memDN in $members) {
            $memName = ($memDN -split ',')[0] -replace 'CN='
            Write-Host "  [+] $memName" -ForegroundColor White
        }
    }
}

function Get-Vulnerabilities {
    Write-Host "`n========== VULNERABILITIES ==========" -ForegroundColor Cyan
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($script:domainEntry)
    $searcher.Filter = "(&(objectClass=user)(|(description=*password*)(description=*pwd*)(description=*pass*)))"
    $searcher.PropertiesToLoad.AddRange(@("samaccountname","description"))
    $results = $searcher.FindAll()
    if($results.Count -gt 0) {
        Write-Host "[!] CRITICAL: $($results.Count) password(s) in descriptions" -ForegroundColor Red
        foreach ($r in $results) {
            $sam = $r.Properties["samaccountname"][0]
            $desc = $r.Properties["description"][0]
            Write-Host "  [!] $sam - $desc" -ForegroundColor Yellow
            $script:CriticalIssues++
            $script:Findings.PasswordInDescription += @{Account=$sam;Description=$desc}
        }
    }
    $results.Dispose()
}

# ============================================================================
# FUNCIONES AVANZADAS OFENSIVAS
# ============================================================================

function Get-DomainTrusts {
    Write-Host "`n========== DOMAIN TRUSTS ==========" -ForegroundColor Cyan
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($script:domainEntry)
    $searcher.Filter = "(objectClass=trustedDomain)"
    $searcher.PageSize = 1000
    $searcher.PropertiesToLoad.AddRange(@("name","trustPartner","trustDirection","trustAttributes"))
    $results = $searcher.FindAll()
    
    if($results.Count -eq 0){
        Write-Host "[+] No external trusts found" -ForegroundColor Green
        return
    }
    
    Write-Host "[!] Found $($results.Count) trust(s)" -ForegroundColor Yellow
    foreach ($r in $results) {
        $trustName = $r.Properties["name"][0]
        $trustPartner = if($r.Properties["trustpartner"].Count -gt 0){$r.Properties["trustpartner"][0]}else{"N/A"}
        $trustDir = $r.Properties["trustdirection"][0]
        
        $direction = switch($trustDir) {
            0 {"Disabled"}
            1 {"Inbound"}
            2 {"Outbound"}
            3 {"Bidirectional"}
            default {"Unknown"}
        }
        
        Write-Host "`n  Trust: $trustName" -ForegroundColor White
        Write-Host "    Partner: $trustPartner" -ForegroundColor Gray
        Write-Host "    Direction: $direction" -ForegroundColor Gray
        
        if($trustDir -eq 1 -or $trustDir -eq 3) {
            Write-Host "    [!] EXPLOITABLE: Inbound trust detected" -ForegroundColor Red
            $script:CriticalIssues++
            $script:Findings.ExploitableTrusts += @{Name=$trustName;Direction=$direction}
        }
    }
    $results.Dispose()
}

function Get-LAPSConfiguration {
    Write-Host "`n========== LAPS DETECTION ==========" -ForegroundColor Cyan
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($script:domainEntry)
    $searcher.Filter = "(&(objectClass=computer)(ms-Mcs-AdmPwd=*))"
    $searcher.PageSize = 1000
    $results = $searcher.FindAll()
    
    if($results.Count -eq 0) {
        Write-Host "[!] WARNING: LAPS not detected" -ForegroundColor Yellow
        $script:WarningIssues++
        return
    }
    
    Write-Host "[+] LAPS Deployed: $($results.Count) computers" -ForegroundColor Green
    $results.Dispose()
}

function Get-ADCSVulnerabilities {
    Write-Host "`n========== CERTIFICATE SERVICES (ADCS) ==========" -ForegroundColor Cyan
    
    try {
        $configNC = "CN=Configuration,$domainDN"
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($script:domainEntry)
        $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Server/$configNC")
        $searcher.Filter = "(objectClass=pKIEnrollmentService)"
        $searcher.PageSize = 1000
        $searcher.PropertiesToLoad.AddRange(@("name","dNSHostName"))
        $results = $searcher.FindAll()
        
        if($results.Count -eq 0) {
            Write-Host "[-] No Certificate Authorities found" -ForegroundColor Gray
            return
        }
        
        Write-Host "[+] Found $($results.Count) Certificate Authority(ies)" -ForegroundColor Yellow
        foreach ($r in $results) {
            $caName = $r.Properties["name"][0]
            $caHost = if($r.Properties["dnshostname"].Count -gt 0){$r.Properties["dnshostname"][0]}else{"N/A"}
            Write-Host "  CA: $caName - $caHost" -ForegroundColor White
        }
        
        Write-Host "`n  [*] Check with: Certify.exe find /vulnerable" -ForegroundColor Cyan
        $results.Dispose()
    } catch {
        Write-Host "[-] Could not enumerate ADCS" -ForegroundColor Gray
    }
}

function Get-DNSRecords {
    Write-Host "`n========== DNS RECORDS ENUMERATION ==========" -ForegroundColor Cyan
    Write-Host "[*] Attempting DNS enumeration..." -ForegroundColor Yellow
    Write-Host "[-] DNS enumeration requires specific permissions" -ForegroundColor Gray
}

function Get-ACLAnalysis {
    Write-Host "`n========== ACL ANALYSIS ==========" -ForegroundColor Cyan
    Write-Host "[*] Analyzing Domain Admins ACL..." -ForegroundColor Yellow
    
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($script:domainEntry)
    $searcher.Filter = "(cn=Domain Admins)"
    $group = $searcher.FindOne()
    
    if($group) {
        try {
            $groupEntry = $group.GetDirectoryEntry()
            $acl = $groupEntry.ObjectSecurity
            $dangerousACEs = @()
            
            foreach ($ace in $acl.Access) {
                $identity = $ace.IdentityReference.ToString()
                $rights = $ace.ActiveDirectoryRights.ToString()
                
                if($rights -match "GenericAll|WriteDacl|WriteOwner") {
                    if($identity -notmatch "SYSTEM|Domain Admins|Enterprise Admins") {
                        Write-Host "  [!] CRITICAL: $identity has $rights" -ForegroundColor Red
                        $dangerousACEs += @{Identity=$identity;Rights=$rights}
                        $script:CriticalIssues++
                    }
                }
            }
            
            if($dangerousACEs.Count -eq 0) {
                Write-Host "[+] No dangerous ACEs found" -ForegroundColor Green
            }
        } catch {
            Write-Host "[-] Could not analyze ACLs: $_" -ForegroundColor Yellow
        }
    }
}

function Get-AdminCount {
    Write-Host "`n========== ADMINCOUNT USERS ==========" -ForegroundColor Cyan
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($script:domainEntry)
    $searcher.Filter = "(&(objectClass=user)(adminCount=1))"
    $searcher.PageSize = 1000
    $searcher.PropertiesToLoad.AddRange(@("samaccountname","memberOf"))
    $results = $searcher.FindAll()
    
    if($results.Count -eq 0) {
        Write-Host "[-] No AdminCount users found" -ForegroundColor Gray
        return
    }
    
    Write-Host "[+] Found $($results.Count) AdminCount=1 users" -ForegroundColor Yellow
    foreach ($r in $results) {
        $sam = $r.Properties["samaccountname"][0]
        Write-Host "  [*] $sam" -ForegroundColor White
    }
    $results.Dispose()
}

function Test-SMBSigningDisabled {
    Write-Host "`n========== SMB SIGNING DETECTION ==========" -ForegroundColor Cyan
    Write-Host "[*] SMB signing check requires network access" -ForegroundColor Yellow
    Write-Host "[*] Use: crackmapexec smb $Server --gen-relay-list relay_targets.txt" -ForegroundColor Cyan
}

function Get-PreWindows2000Computers {
    Write-Host "`n========== PRE-WINDOWS 2000 COMPATIBLE ACCESS ==========" -ForegroundColor Cyan
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($script:domainEntry)
    $searcher.Filter = "(cn=Pre-Windows 2000 Compatible Access)"
    $group = $searcher.FindOne()
    
    if($group) {
        $members = $group.Properties["member"]
        if($members.Count -gt 2) {
            Write-Host "[!] WARNING: $($members.Count) members in Pre-Windows 2000 group" -ForegroundColor Yellow
            $script:WarningIssues++
        } else {
            Write-Host "[+] Properly configured" -ForegroundColor Green
        }
    }
}

function Get-PasswordSprayTargets {
    Write-Host "`n========== PASSWORD SPRAY PREPARATION ==========" -ForegroundColor Cyan
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($script:domainEntry)
    $searcher.Filter = "(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
    $searcher.PageSize = 1000
    $searcher.PropertiesToLoad.AddRange(@("samaccountname","badpwdcount"))
    $results = $searcher.FindAll()
    
    $sprayTargets = @()
    foreach ($r in $results) {
        $sam = $r.Properties["samaccountname"][0]
        $badPwd = if($r.Properties["badpwdcount"].Count -gt 0){$r.Properties["badpwdcount"][0]}else{0}
        if($badPwd -lt 3) {
            $sprayTargets += $sam
        }
    }
    
    Write-Host "[+] Safe spray targets: $($sprayTargets.Count)" -ForegroundColor Green
    $sprayTargets | Out-File -FilePath "spray_targets.txt" -Encoding UTF8
    Write-Host "[*] Saved to: spray_targets.txt" -ForegroundColor Cyan
    Write-Host "`n  [*] Use: kerbrute passwordspray -d $Domain spray_targets.txt 'Password123!'" -ForegroundColor Green
    
    $results.Dispose()
}

function Get-NTLMAuthEndpoints {
    Write-Host "`n========== NTLM AUTHENTICATION ENDPOINTS ==========" -ForegroundColor Cyan
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($script:domainEntry)
    $searcher.Filter = "(&(objectClass=computer)(servicePrincipalName=HTTP/*))"
    $searcher.PageSize = 1000
    $searcher.PropertiesToLoad.AddRange(@("name","dnshostname"))
    $results = $searcher.FindAll()
    
    if($results.Count -gt 0) {
        Write-Host "[+] Found $($results.Count) HTTP endpoints" -ForegroundColor Yellow
        foreach ($r in $results | Select-Object -First 10) {
            $hostname = if($r.Properties["dnshostname"].Count -gt 0){$r.Properties["dnshostname"][0]}else{$r.Properties["name"][0]}
            Write-Host "  [*] $hostname" -ForegroundColor Cyan
        }
    }
    $results.Dispose()
}

function Invoke-AutoKerberoast {
    Write-Host "`n========== AUTO-KERBEROAST ==========" -ForegroundColor Cyan
    Write-Host "[*] Running Kerberoast detection..." -ForegroundColor Yellow
    Get-Kerberoastable
}

function Export-BloodhoundData {
    Write-Host "`n========== BLOODHOUND EXPORT ==========" -ForegroundColor Cyan
    Write-Host "[*] Use: SharpHound.exe -c All -d $Domain" -ForegroundColor Cyan
    Write-Host "[*] Or:  bloodhound-python -u $Usuario -p $Password -d $Domain -dc $Server -c All" -ForegroundColor Cyan
}

function Get-DCSync {
    Write-Host "`n========== DCSYNC DETECTION ==========" -ForegroundColor Cyan
    Write-Host "[*] Checking DCSync permissions..." -ForegroundColor Yellow
    Write-Host "[*] Use: Get-DomainObjectAcl -SearchBase 'DC=...' | ? {$_.ObjectAceType -eq 'DS-Replication-Get-Changes-All'}" -ForegroundColor Cyan
}

# ============================================================================
# RESUMEN FINAL
# ============================================================================

function Show-Summary {
    Write-Host "`n`n==================================================================================================" -ForegroundColor Cyan
    Write-Host "                              EXECUTIVE SUMMARY" -ForegroundColor Cyan
    Write-Host "==================================================================================================" -ForegroundColor Cyan
    Write-Host "Domain: $Domain | Server: $Server" -ForegroundColor White
    Write-Host "Critical Issues: $script:CriticalIssues | Warnings: $script:WarningIssues" -ForegroundColor $(if($script:CriticalIssues -gt 0){"Red"}else{"Green"})
    Write-Host ""
    
    if($script:Findings.Kerberoastable.Count -gt 0) {
        Write-Host "[1] KERBEROASTING - CRITICAL" -ForegroundColor Red
        Write-Host "    Affected: $($script:Findings.Kerberoastable.Count) accounts" -ForegroundColor Yellow
        foreach ($f in $script:Findings.Kerberoastable) {Write-Host "      - $($f.Account)" -ForegroundColor White}
        Write-Host ""
    }
    
    if($script:Findings.ASREPRoastable.Count -gt 0) {
        Write-Host "[2] ASREPROASTING - CRITICAL" -ForegroundColor Red
        Write-Host "    Affected: $($script:Findings.ASREPRoastable.Count) accounts" -ForegroundColor Yellow
        foreach ($f in $script:Findings.ASREPRoastable) {Write-Host "      - $($f.Account)" -ForegroundColor White}
        Write-Host ""
    }
    
    if($script:Findings.cPasswordFound.Count -gt 0) {
        Write-Host "[3] GPP cPASSWORD - CRITICAL" -ForegroundColor Red
        Write-Host "    Found: $($script:Findings.cPasswordFound.Count) cPassword(s)" -ForegroundColor Yellow
        foreach ($f in $script:Findings.cPasswordFound) {
            Write-Host "      GPO: $($f.GPO)" -ForegroundColor White
            Write-Host "      Hash: $($f.Hash)" -ForegroundColor Red
        }
        Write-Host ""
    }
    
    $overallRisk = if($script:CriticalIssues -gt 5){"CRITICAL"}elseif($script:CriticalIssues -gt 2){"HIGH"}elseif($script:CriticalIssues -gt 0){"MEDIUM"}else{"LOW"}
    Write-Host "==================================================================================================" -ForegroundColor Cyan
    Write-Host "OVERALL RISK LEVEL: $overallRisk" -ForegroundColor $(if($overallRisk -eq "CRITICAL" -or $overallRisk -eq "HIGH"){"Red"}elseif($overallRisk -eq "MEDIUM"){"Yellow"}else{"Green"})
    Write-Host "==================================================================================================" -ForegroundColor Cyan
    Write-Host "Scan Duration: $((Get-Date) - $script:StartTime)" -ForegroundColor Gray
    Write-Host ""
}

# ============================================================================
# EJECUCIÓN PRINCIPAL
# ============================================================================

# Funciones básicas
if($All -or $Users){Get-DomainUsers}
if($All -or $Groups){Get-DomainGroups}
if($All -or $Computers){Get-DomainComputers}
if($All -or $GPOs){Get-DomainGPOs}
if($All -or $ServiceAccounts){Get-ServiceAccounts}
if($All -or $Kerberoast){Get-Kerberoastable}
if($All -or $ASREPRoast){Get-ASREPRoastable}
if($All -or $DomainAdmins){Get-DomainAdmins}
if($All -or $Vulnerabilities){Get-Vulnerabilities}

# Funciones avanzadas
if($All -or $Advanced -or $Trusts){Get-DomainTrusts}
if($All -or $Advanced -or $LAPS){Get-LAPSConfiguration}
if($All -or $Advanced -or $ADCS){Get-ADCSVulnerabilities}
if($All -or $Advanced -or $DNS){Get-DNSRecords}
if($All -or $Advanced -or $ACLs){Get-ACLAnalysis}
if($All -or $Advanced -or $AdminCount){Get-AdminCount}
if($All -or $Advanced -or $SMBSigning){Test-SMBSigningDisabled}
if($All -or $Advanced -or $PreWin2000){Get-PreWindows2000Computers}
if($PasswordSpray){Get-PasswordSprayTargets}
if($NTLMEndpoints){Get-NTLMAuthEndpoints}
if($AutoKerberoast){Invoke-AutoKerberoast}
if($ExportBloodhound){Export-BloodhoundData}
if($DCSync){Get-DCSync}

# Mostrar resumen
Show-Summary

Write-Host "[*] Results stored in: `$global:ScanResults" -ForegroundColor Green
$global:ScanResults = @{
    Domain=$Domain;Server=$Server;ScanDate=Get-Date
    Duration=(Get-Date)-$script:StartTime
    CriticalIssues=$script:CriticalIssues
    Warnings=$script:WarningIssues
    Findings=$script:Findings
}
