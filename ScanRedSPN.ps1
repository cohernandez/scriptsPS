# ============================================================================
# Script d'analyse des réseaux via SPN - Version Complète avec Menu
# Author: Pentest Team
# Version: 2.1
# ============================================================================

param(
    [Parameter(Mandatory=$false)]
    [string]$Domain,
    
    [string]$OutputFile = "network_analysis.txt",
    
    [switch]$SaveSPN,
    
    [switch]$Verbose,
    
    [int]$MinHostsForNet20 = 5,
    
    [switch]$Help
)

# ============================================================================
# FONCTION D'AIDE
# ============================================================================

function Show-Help {
    Clear-Host
    Write-Host @"

╔════════════════════════════════════════════════════════════════════════════╗
║                                                                            ║
║              ANALYSEUR DE RÉSEAUX VIA SERVICE PRINCIPAL NAMES              ║
║                           Version 2.1 - 2026                               ║
║                                                                            ║
╚════════════════════════════════════════════════════════════════════════════╝

DESCRIPTION:
    Ce script analyse les Service Principal Names (SPN) d'un domaine Active 
    Directory pour identifier et cartographier les réseaux et sous-réseaux.

SYNOPSIS:
    .\analyze_spn.ps1 -Domain <domaine> [OPTIONS]

PARAMÈTRES:

    -Domain <string>           [OBLIGATOIRE]
        Nom du domaine Active Directory à analyser
        Exemple: "megacorp.local", "contoso.com"

    -OutputFile <string>       [OPTIONNEL]
        Nom du fichier de sortie (défaut: network_analysis.txt)
        Génère automatiquement .json et .csv

    -SaveSPN                   [OPTIONNEL]
        Sauvegarde la sortie brute de setspn dans un fichier

    -Verbose                   [OPTIONNEL]
        Affiche des informations détaillées pendant l'exécution

    -MinHostsForNet20 <int>    [OPTIONNEL]
        Seuil minimum d'hôtes pour identifier un réseau /20 (défaut: 5)

    -Help                      [OPTIONNEL]
        Affiche ce menu d'aide

EXEMPLES D'UTILISATION:

    1. Analyse basique:
       .\analyze_spn.ps1 -Domain "megacorp.local"

    2. Analyse avec sauvegarde des SPN:
       .\analyze_spn.ps1 -Domain "contoso.com" -SaveSPN

    3. Analyse détaillée avec mode verbeux:
       .\analyze_spn.ps1 -Domain "lab.local" -Verbose

    4. Analyse avec fichier de sortie personnalisé:
       .\analyze_spn.ps1 -Domain "corp.domain.com" -OutputFile "rapport_corp.txt"

    5. Analyse complète avec toutes les options:
       .\analyze_spn.ps1 -Domain "megacorp.local" -SaveSPN -Verbose `
                         -MinHostsForNet20 10 -OutputFile "analyse_complete.txt"

    6. Modifier le seuil de détection des réseaux /20:
       .\analyze_spn.ps1 -Domain "domain.local" -MinHostsForNet20 15

FONCTIONNALITÉS:

    ✓ Extraction automatique des SPN via setspn
    ✓ Résolution DNS des hôtes identifiés
    ✓ Détection des sous-réseaux /24 et /20
    ✓ Statistiques détaillées par réseau
    ✓ Export multi-formats (TXT, JSON, CSV)
    ✓ Cartographie complète de l'infrastructure
    ✓ Barre de progression en temps réel

SORTIES GÉNÉRÉES:

    • network_analysis.txt     → Rapport texte formaté
    • network_analysis.json    → Données structurées JSON
    • network_analysis.csv     → Tableau CSV pour Excel
    • spn_dump_*.txt          → Dump brut des SPN (si -SaveSPN)

PRÉREQUIS:

    • Exécution sur un système joint au domaine
    • Compte avec permissions de lecture AD
    • PowerShell 5.1 ou supérieur
    • Module Active Directory (recommandé)

PHASES D'EXÉCUTION:

    [PHASE 1] Extraction des SPN depuis Active Directory
    [PHASE 2] Identification des hôtes uniques
    [PHASE 3] Résolution DNS de tous les hôtes
    [PHASE 4] Analyse et regroupement par sous-réseaux
    [PHASE 5] Génération des statistiques
    [PHASE 6] Répartition par plages IP
    [PHASE 7] Export des rapports multi-formats

UTILISATION DANS UN PENTEST:

    Ce script est particulièrement utile pour:
    • Cartographier l'infrastructure réseau
    • Identifier les segments critiques
    • Localiser les serveurs de services
    • Préparer les phases de mouvement latéral
    • Documenter la surface d'attaque

NOTES DE SÉCURITÉ:

    ⚠ Ce script effectue des requêtes DNS massives
    ⚠ Les actions sont journalisées dans les logs AD
    ⚠ Utiliser uniquement dans un cadre autorisé

CONTACT & SUPPORT:

    Pour plus d'informations ou rapporter un bug:
    • Documentation: https://github.com/pentest/analyze-spn
    • Email: pentest-team@organization.com

╔════════════════════════════════════════════════════════════════════════════╗
║  Appuyez sur une touche pour quitter ou relancez avec -Domain <domaine>   ║
╚════════════════════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan

    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 0
}

# ============================================================================
# VALIDATION DES PARAMÈTRES
# ============================================================================

if ($Help -or -not $Domain) {
    Show-Help
}

# ============================================================================
# FONCTIONS AUXILIAIRES
# ============================================================================

function Write-Phase {
    param([int]$Number, [string]$Text)
    Write-Host "`n[PHASE $Number] " -ForegroundColor Yellow -NoNewline
    Write-Host "$Text" -ForegroundColor Cyan
}

function Write-Section {
    param([string]$Text)
    Write-Host "`n[*] $Text" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Text)
    Write-Host "    $Text" -ForegroundColor Green
}

function Write-Info {
    param([string]$Text)
    Write-Host "    $Text" -ForegroundColor White
}

function Write-Banner {
    Write-Host @"

╔════════════════════════════════════════════════════════════════════════════╗
║                                                                            ║
║              ANALYSEUR DE RÉSEAUX VIA SERVICE PRINCIPAL NAMES              ║
║                                                                            ║
║  Domaine cible: $($Domain.PadRight(58)) ║
║  Date: $($(Get-Date -Format "dd/MM/yyyy HH:mm:ss").PadRight(64)) ║
║                                                                            ║
╚════════════════════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Green
}

function Get-NetworkCIDR {
    param(
        [string]$IP,
        [int]$Prefix
    )
    
    try {
        $octets = $IP.Split('.')
        if ($octets.Count -ne 4) { return $null }
        
        $mask = [Convert]::ToUInt32(('1' * $Prefix).PadRight(32, '0'), 2)
        
        $ipInt = ([uint32]$octets[0] -shl 24) + 
                 ([uint32]$octets[1] -shl 16) + 
                 ([uint32]$octets[2] -shl 8) + 
                 [uint32]$octets[3]
        
        $networkInt = $ipInt -band $mask
        
        $oct1 = ($networkInt -shr 24) -band 0xFF
        $oct2 = ($networkInt -shr 16) -band 0xFF
        $oct3 = ($networkInt -shr 8) -band 0xFF
        $oct4 = $networkInt -band 0xFF
        
        return "$oct1.$oct2.$oct3.$oct4/$Prefix"
    }
    catch {
        return $null
    }
}

# ============================================================================
# BANNER
# ============================================================================

Clear-Host
Write-Banner

# ============================================================================
# INITIALISATION DES STRUCTURES DE DONNÉES
# ============================================================================

$hostData = @{}
$networks24 = @{}
$networks20 = @{}
$allIPs = @()
$spnLines = @()
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$startTime = Get-Date

# ============================================================================
# PHASE 1: EXTRACTION DES SPN
# ============================================================================

Write-Phase -Number 1 -Text "EXTRACTION DES SPN"

try {
    Write-Info "Exécution de: setspn -T $Domain -Q */*"
    
    $spnOutput = setspn -T $Domain -Q */* 2>&1
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "`n[!] ERREUR: Impossible d'exécuter setspn (Code: $LASTEXITCODE)" -ForegroundColor Red
        Write-Host "[!] Vérifications nécessaires:" -ForegroundColor Yellow
        Write-Host "    • Êtes-vous connecté au domaine ?" -ForegroundColor Yellow
        Write-Host "    • Avez-vous les permissions de lecture AD ?" -ForegroundColor Yellow
        Write-Host "    • Le domaine '$Domain' est-il correct ?" -ForegroundColor Yellow
        exit 1
    }
    
    $spnLines = $spnOutput | Where-Object { $_ -match '^[A-Za-z0-9_-]+/' }
    
    if ($SaveSPN) {
        $spnFile = "spn_dump_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
        $spnOutput | Out-File $spnFile -Encoding UTF8
        Write-Info "SPN sauvegardés dans: $spnFile"
    }
    
    Write-Info "* $($spnLines.Count) entrées SPN extraites"
    
    if ($spnLines.Count -eq 0) {
        Write-Host "`n[!] ATTENTION: Aucun SPN trouvé dans le domaine '$Domain'" -ForegroundColor Red
        Write-Host "[!] Causes possibles:" -ForegroundColor Yellow
        Write-Host "    • Le domaine n'existe pas ou nom incorrect" -ForegroundColor Yellow
        Write-Host "    • Aucun service enregistré dans AD" -ForegroundColor Yellow
        Write-Host "    • Permissions insuffisantes" -ForegroundColor Yellow
        exit 1
    }
}
catch {
    Write-Host "`n[!] ERREUR CRITIQUE: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# ============================================================================
# PHASE 2: EXTRACTION DES HÔTES UNIQUES
# ============================================================================

Write-Phase -Number 2 -Text "EXTRACTION DES HÔTES"

$uniqueHosts = @{}
$spnPatterns = @(
    '^([A-Za-z0-9_-]+)/([^:/@\s]+)',
    '^([A-Za-z0-9_-]+)/([^:/@\s]+):(\d+)',
    '^([A-Za-z0-9_-]+)/([^:/@\s]+)/([^:/@\s]+)'
)

foreach ($line in $spnLines) {
    foreach ($pattern in $spnPatterns) {
        if ($line -match $pattern) {
            $hostname = $matches[2].ToLower().Trim()
            
            $isValid = $hostname -notmatch '^(localhost|127\.|169\.254\.)' -and
                       $hostname.Contains('.') -and
                       $hostname -notmatch '^\d+\.\d+\.\d+\.\d+$' -and
                       $hostname.Length -gt 0
            
            if ($isValid) {
                $uniqueHosts[$hostname] = $true
                if ($Verbose) {
                    Write-Host "    [+] Hôte trouvé: $hostname" -ForegroundColor DarkGray
                }
            }
            break
        }
    }
}

Write-Info "* $($uniqueHosts.Count) hôtes uniques identifiés"

if ($uniqueHosts.Count -eq 0) {
    Write-Host "`n[!] ERREUR: Aucun hôte valide trouvé dans les SPN" -ForegroundColor Red
    exit 1
}

# ============================================================================
# PHASE 3: RÉSOLUTION DNS
# ============================================================================

Write-Phase -Number 3 -Text "RÉSOLUTION DNS"

$resolvedCount = 0
$failedCount = 0
$failedHosts = @()
$progress = 0
$totalHosts = $uniqueHosts.Count

Write-Info "Résolution de $totalHosts hôtes en cours..."

foreach ($hostname in $uniqueHosts.Keys) {
    $progress++
    $percentComplete = [Math]::Round(($progress / $totalHosts) * 100, 2)
    
    Write-Progress -Activity "Résolution DNS en cours" `
                   -Status "[$progress/$totalHosts] $hostname" `
                   -PercentComplete $percentComplete
    
    try {
        $dnsResult = [System.Net.Dns]::GetHostAddresses($hostname)
        $ipv4Addresses = $dnsResult | Where-Object { $_.AddressFamily -eq 'InterNetwork' }
        
        if ($ipv4Addresses -and $ipv4Addresses.Count -gt 0) {
            $ipString = $ipv4Addresses[0].IPAddressToString
            
            if ($ipString -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
                $hostData[$hostname] = $ipString
                $allIPs += $ipString
                
                $net24 = Get-NetworkCIDR -IP $ipString -Prefix 24
                if ($net24) {
                    if (-not $networks24.ContainsKey($net24)) {
                        $networks24[$net24] = @()
                    }
                    $networks24[$net24] += @{
                        IP = $ipString
                        Host = $hostname
                    }
                }
                
                $net20 = Get-NetworkCIDR -IP $ipString -Prefix 20
                if ($net20) {
                    if (-not $networks20.ContainsKey($net20)) {
                        $networks20[$net20] = 0
                    }
                    $networks20[$net20]++
                }
                
                $resolvedCount++
                
                if ($Verbose) {
                    Write-Host "    [✓] $hostname -> $ipString" -ForegroundColor DarkGreen
                }
            }
        }
        else {
            $failedCount++
            $failedHosts += $hostname
            if ($Verbose) {
                Write-Host "    [✗] $hostname (pas d'IPv4)" -ForegroundColor DarkYellow
            }
        }
    }
    catch {
        $failedCount++
        $failedHosts += $hostname
        if ($Verbose) {
            Write-Host "    [✗] $hostname (échec DNS)" -ForegroundColor DarkRed
        }
    }
}

Write-Progress -Activity "Résolution DNS" -Completed

Write-Info "* IPs résolues: $resolvedCount"
if ($failedCount -gt 0) {
    Write-Host "    * Échecs DNS: $failedCount" -ForegroundColor Yellow
}

if ($resolvedCount -eq 0) {
    Write-Host "`n[!] ERREUR: Aucune IP résolue. Impossible de continuer." -ForegroundColor Red
    exit 1
}

# ============================================================================
# PHASE 4: ANALYSE DES SOUS-RÉSEAUX
# ============================================================================

Write-Phase -Number 4 -Text "ANALYSE DES SOUS-RÉSEAUX"

Write-Section "Sous-réseaux /24 détectés:"
$sortedNetworks24 = $networks24.GetEnumerator() | 
                    Sort-Object {$_.Value.Count} -Descending

foreach ($net in $sortedNetworks24) {
    $count = $net.Value.Count
    Write-Success "$($net.Key) → $count machines"
}

$probableNetworks20 = $networks20.GetEnumerator() | 
                      Where-Object {$_.Value -ge $MinHostsForNet20} | 
                      Sort-Object Value -Descending

if ($probableNetworks20 -and $probableNetworks20.Count -gt 0) {
    Write-Section "Sous-réseaux /20 probables:"
    foreach ($net in $probableNetworks20) {
        Write-Success "$($net.Key)"
    }
}
else {
    Write-Section "Sous-réseaux /20 probables:"
    Write-Info "Aucun sous-réseau /20 détecté (seuil: $MinHostsForNet20 machines)"
}

# ============================================================================
# PHASE 5: STATISTIQUES
# ============================================================================

Write-Phase -Number 5 -Text "STATISTIQUES"
Write-Info "* $($sortedNetworks24.Count)"

# ============================================================================
# PHASE 6: RÉPARTITION PAR PLAGE IP
# ============================================================================

Write-Phase -Number 6 -Text "RÉPARTITION PAR PLAGE IP"

$ipRanges = @{}
foreach ($ip in $allIPs) {
    $octets = $ip.Split('.')
    if ($octets.Count -eq 4) {
        $range = "$($octets[0]).$($octets[1]).x.x"
        if (-not $ipRanges.ContainsKey($range)) {
            $ipRanges[$range] = 0
        }
        $ipRanges[$range]++
    }
}

Write-Section "Répartition par plage IP:"
$ipRanges.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object {
    Write-Success "$($_.Key) → $($_.Value) machines"
}

# ============================================================================
# PHASE 7: GÉNÉRATION DES RAPPORTS
# ============================================================================

Write-Phase -Number 7 -Text "GÉNÉRATION RAPPORTS"

# ============================================================================
# RÉSUMÉ FINAL
# ============================================================================

Write-Host @"

╔════════════════════════════════════════════════════════════════════════════╗
║                            RÉSUMÉ FINAL                                    ║
╚════════════════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Green

$uniqueIPs = $allIPs | Select-Object -Unique
Write-Host "`n[*] Total machines: $($allIPs.Count)" -ForegroundColor Cyan
Write-Host "[*] IPs résolues: $($uniqueIPs.Count)" -ForegroundColor Cyan
Write-Host "[*] Réseaux /24 uniques: $($networks24.Count)" -ForegroundColor Cyan
Write-Host "[*] Réseaux /20 probables: $($probableNetworks20.Count)" -ForegroundColor Cyan

# ============================================================================
# EXPORT FICHIER TEXTE
# ============================================================================

$output = @"
=======================================
   ANALYSE DES RÉSEAUX VIA SPN
   Domaine: $Domain
   Date: $timestamp
=======================================

[PHASE 1] EXTRACTION DES SPN
    * $($spnLines.Count) entrées SPN extraites

[PHASE 2] EXTRACTION DES HÔTES
    * $($uniqueHosts.Count) hôtes uniques identifiés

[PHASE 3] RÉSOLUTION DNS
    * IPs résolues: $resolvedCount
    * Échecs DNS: $failedCount

[*] Sous-réseaux /24 détectés:
$($sortedNetworks24 | ForEach-Object { 
    "    $($_.Key) → $($_.Value.Count) machines" 
} | Out-String)

[*] Sous-réseaux /20 probables:
$($probableNetworks20 | ForEach-Object { 
    "    $($_.Key)" 
} | Out-String)

[PHASE 5] STATISTIQUES
    * $($sortedNetworks24.Count)

[*] Répartition par plage IP:
$($ipRanges.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object { 
    "    $($_.Key) → $($_.Value) machines" 
} | Out-String)

=======================================
            RÉSUMÉ FINAL
=======================================

[*] Total machines: $($allIPs.Count)
[*] IPs résolues: $($uniqueIPs.Count)
[*] Réseaux /24 uniques: $($networks24.Count)
[*] Réseaux /20 probables: $($probableNetworks20.Count)

=======================================
       DÉTAILS PAR RÉSEAU /24
=======================================
$($sortedNetworks24 | ForEach-Object {
    $netName = $_.Key
    "`nRéseau: $netName ($($_.Value.Count) machines)"
    $_.Value | Sort-Object {$_.IP} | ForEach-Object {
        "    - $($_.Host) [$($_.IP)]"
    }
} | Out-String)
"@

try {
    $output | Out-File -FilePath $OutputFile -Encoding UTF8
    Write-Info "✓ Rapport texte: $OutputFile"
}
catch {
    Write-Host "[!] Erreur lors de l'export TXT: $($_.Exception.Message)" -ForegroundColor Red
}

# ============================================================================
# EXPORT JSON
# ============================================================================

$jsonReport = @{
    Metadata = @{
        Timestamp = $timestamp
        Domain = $Domain
        ScriptVersion = "2.1"
        ExecutionTime = "$([Math]::Round(((Get-Date) - $startTime).TotalSeconds, 2)) secondes"
    }
    Statistics = @{
        TotalMachines = $allIPs.Count
        UniqueIPs = $uniqueIPs.Count
        ResolvedHosts = $resolvedCount
        FailedDNS = $failedCount
        Networks24Count = $networks24.Count
        Networks20Count = $probableNetworks20.Count
    }
    Networks24 = @($sortedNetworks24 | ForEach-Object {
        @{
            Network = $_.Key
            Count = $_.Value.Count
            Hosts = @($_.Value | Sort-Object {$_.IP} | ForEach-Object {
                @{
                    Hostname = $_.Host
                    IP = $_.IP
                }
            })
        }
    })
    Networks20 = @($probableNetworks20 | ForEach-Object {
        @{
            Network = $_.Key
            Count = $_.Value
        }
    })
    IPRanges = @($ipRanges.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object {
        @{
            Range = $_.Key
            Count = $_.Value
        }
    })
    FailedHosts = $failedHosts
}

$jsonFile = $OutputFile -replace '\.txt$', '.json'
try {
    $jsonReport | ConvertTo-Json -Depth 10 | Out-File $jsonFile -Encoding UTF8
    Write-Info "✓ Rapport JSON: $jsonFile"
}
catch {
    Write-Host "[!] Erreur lors de l'export JSON: $($_.Exception.Message)" -ForegroundColor Red
}

# ============================================================================
# EXPORT CSV
# ============================================================================

$csvData = @()
foreach ($host in $hostData.GetEnumerator()) {
    $ip = $host.Value
    $net24 = Get-NetworkCIDR -IP $ip -Prefix 24
    $net20 = Get-NetworkCIDR -IP $ip -Prefix 20
    $octets = $ip.Split('.')
    $range = "$($octets[0]).$($octets[1]).x.x"
    
    $csvData += [PSCustomObject]@{
        Hostname = $host.Key
        IP = $ip
        Network24 = $net24
        Network20 = $net20
        IPRange = $range
    }
}

$csvFile = $OutputFile -replace '\.txt$', '.csv'
try {
    $csvData | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
    Write-Info "✓ Rapport CSV: $csvFile"
}
catch {
    Write-Host "[!] Erreur lors de l'export CSV: $($_.Exception.Message)" -ForegroundColor Red
}

# ============================================================================
# FINALISATION
# ============================================================================

$endTime = Get-Date
$executionTime = ($endTime - $startTime).TotalSeconds

Write-Host @"

╔════════════════════════════════════════════════════════════════════════════╗
║                        ANALYSE TERMINÉE AVEC SUCCÈS                        ║
╚════════════════════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Green

Write-Host "[✓] Temps d'exécution: $([Math]::Round($executionTime, 2)) secondes`n" -ForegroundColor Green

Write-Host "Fichiers générés dans: $(Get-Location)" -ForegroundColor White
Write-Host "  → $OutputFile" -ForegroundColor Gray
Write-Host "  → $jsonFile" -ForegroundColor Gray
Write-Host "  → $csvFile" -ForegroundColor Gray

if ($SaveSPN) {
    Write-Host "  → spn_dump_*.txt" -ForegroundColor Gray
}

Write-Host @"

╔════════════════════════════════════════════════════════════════════════════╗
║  Pour afficher l'aide: .\analyze_spn.ps1 -Help                            ║
╚════════════════════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan
