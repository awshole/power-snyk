[CmdletBinding()]
Param
(
    [Parameter(Mandatory = $True)] [string] $dotSourceFilePath,        
    [Parameter(Mandatory = $True)] [string] $pathToSnykIssues,
    [Parameter(Mandatory = $True)] [string] $pathToDependencyFile,
    [Parameter(Mandatory = $True)] [string] $branch,
    [Parameter(Mandatory = $True)] [string] $gitHubToken,
    [Parameter(Mandatory = $True)] [string] $repository
)

if (Test-Path -Path $dotSourceFilePath) {
    try {
        . $dotSourceFilePath
    } catch {
        Write-Warning "Unable to dot source file: $dotSourceFilePath."
        $ErrorMessage = $_.Exception.Message
        Write-Warning "$ErrorMessage"
        break
    }
} else {
    Write-Warning "Could not find path to file: $dotSourceFilePath."
    $ErrorMessage = $_.Exception.Message
    Write-Warning "$ErrorMessage"
    break
}

$dependencyContent = Get-Content $pathToDependencyFile
$projectIssues = Get-Content -Path $pathToSnykIssues | ConvertFrom-Json -AsHashTable
$issues = $projectIssues.vulnerabilities
[array]$upgradableIssues = $issues | Where-Object {($_.upgradePath.Count -gt 0 -or $_.patches.Count -gt 0 -or $_.fixedIn.Count -gt 0)}
[array]$allUpgradablePackages = $upgradableIssues.from | Select-Object -Unique
[array]$nonUpgradableIssues = $issues | Where-Object {($_.upgradePath.Count -eq 0) -and ($_.type -notlike 'license') -and ($_.patches.Count -eq 0) -and ($_.fixedIn.Count -eq 0)}
[array]$allNonUpgradablePackages = $nonUpgradableIssues.from | Select-Object -Unique

foreach ($package in $allUpgradablePackages) {
    $packageName = $package.split('@')[0]
    $packageVersion = $package.split('@')[-1].Trim()
    $pattern = "$packageName[^-_].*\d"
    if ($dependencyContent -match $pattern) {
        [array]$upgradablePackages += [PSCustomObject]@{
            packageName = $packageName
            packageVersion = $packageVersion
            pattern = $pattern
            startLine = $dependencyContent.IndexOf(($dependencyContent | Select-String -Pattern $pattern)) + 1
            endLine = $dependencyContent.IndexOf(($dependencyContent | Select-String -Pattern $pattern)) + 1
            startColumn = ($dependencyContent | Select-String -Pattern $pattern).Line.Length - ($dependencyContent -match $pattern).TrimStart().Length
            endColumn = ($dependencyContent | Select-String -Pattern $pattern).Line.Length + 1
        }
    }
}

foreach ($package in $allNonUpgradablePackages) {
    $packageVersion = $package.split('@')[-1].Trim()
    $pattern = "$packageName[^-_].*\d"
    if ($dependencyContent -match $pattern) {
        [array]$upgradablePackages += [PSCustomObject]@{
            packageName = $packageName
            packageVersion = $packageVersion
            pattern = $pattern
            startLine = $dependencyContent.IndexOf(($dependencyContent | Select-String -Pattern $pattern)) + 1
            endLine = $dependencyContent.IndexOf(($dependencyContent | Select-String -Pattern $pattern)) + 1
            startColumn = ($dependencyContent | Select-String -Pattern $pattern).Line.Length - ($dependencyContent -match $pattern).TrimStart().Length
            endColumn = ($dependencyContent | Select-String -Pattern $pattern).Line.Length + 1
        }
    }
}

foreach ($package in $upgradablePackages) {
    [array]$remediatedIssues = $upgradableIssues | Where-Object {$_.from -contains "$($package.packageName)@$($package.packageVersion)"}
    $allIssueData = $null
    foreach ($issue in $remediatedIssues) {       
        $issueData = [PSCustomObject][ordered]@{
            'Vulnerable Package' = $issue.Name
            id = $issue.id
            Description = $issue.description
            Version = $issue.version
            title = "$($issue.title)"
            Severity = $issue.severity
            'Exploit Maturity' = $issue.exploit
            CVE = "<a href=`"https://cve.mitre.org/cgi-bin/cvename.cgi?name=$($issue.identifiers.CVE)`">$($issue.title)</a>"
            'CVSS Score' = $issue.cvssScore
            language = $issue.language
            'From' = $issue.from -join ' 🠆 ' | Out-String
            objFrom = $issue.from
            'Fixed In' = $issue.fixedIn -join ', ' | Out-String
        }
        [array]$allIssueData += $issueData
    }

    if ($allIssueData.severity -contains 'high') {
        $level = 'error'
    } elseif ($allIssueData.severity -contains 'medium') {
        $level = 'warning'
    } elseif ($allIssueData.severity -contains 'low') {
        $level = 'note'
    }
    
    Add-Type -AssemblyName System.Web
    $table = [System.Web.HttpUtility]::HtmlDecode(($allIssueData | Select-Object -Property * -ExcludeProperty labels, language, title, id, objFrom, Description | Sort-Object -Property 'CVSS Score' -Descending | ConvertTo-Html -Fragment)) | Out-String
    [array]$uniqueDescriptions = $allissueData.Description | Select-Object -Unique 
    [string]$details = $uniqueDescriptions -join "$([Environment]::NewLine; [Environment]::NewLine)---$([Environment]::NewLine; [Environment]::NewLine)" | Out-String
    [string]$markdown = "All of the vulnerabilities are listed below

$table"
    [array]$rules += [PSCustomObject]@{
        id = "update-$($package.packageName)-$($package.packageVersion)"
        name = (Get-Culture).TextInfo.ToTitleCase("Update $($package.packageName.Replace('-', ' '))") -Replace ' '
        helpUri = "https://security.snyk.io/vuln/$($package.id)"
        shortDescription = [PSCustomObject]@{
            text = "$($package.packageName) $($package.packageVersion) is vulnerable and can be upgraded"
        }
        fullDescription = [PSCustomObject]@{
            text = "$($package.packageName) $($package.packageVersion) contains $($allIssueData.count) issues"
        }
        help = [PSCustomObject]@{
            text = ''
            markdown = "$markdown"
        }
        defaultConfiguration = [PSCustomObject]@{
            level = $level
        }
        properties = [PSCustomObject]@{
            tag = @('snyk', 'source composition analysis', 'security')
        }
    }
    $locations = [PSCustomObject]@{
        physicalLocation = [PSCustomObject]@{
            artifactLocation = [PSCustomObject]@{
                uri = "$pathToDependencyFile"
            }
            region = [PSCustomObject]@{
                startLine = $package.startLine
                endLine = $package.endLine
                startColumn = $package.startColumn
                endColumn = $package.endColumn
            }
        }
    }
    [array] $results += [PSCustomObject]@{
        ruleId = "update-$($package.packageName)-$($package.packageVersion)"
        message = [PSCustomObject]@{
            text = "Update $($package.packageName) $($package.packageVersion)"
        }
        locations = @($locations)
    } 
}

foreach ($package in $nonUpgradablePackages) {
    [array]$nonFixableIssues = $nonUpgradableIssues | Where-Object {$_.from -contains "$($package.packageName)@$($package.packageVersion)"}
    $allIssueData = $null
    foreach ($issue in $nonFixableIssues) {       
        $issueData = [PSCustomObject][ordered]@{
            'Vulnerable Package' = $issue.Name
            id = $issue.id
            Description = $issue.description
            Version = $issue.version
            title = "$($issue.title)"
            Severity = $issue.severity
            'Exploit Maturity' = $issue.exploit
            CVE = "<a href='https://cve.mitre.org/cgi-bin/cvename.cgi?name=$($issue.identifiers.CVE)'>$($issue.title)</a>"
            'CVSS Score' = $issue.cvssScore
            language = $issue.language
            'From' = $issue.from -join ' 🠆 ' | Out-String
            objFrom = $issue.from
            'Fixed In' = $issue.fixedIn -join ', ' | Out-String
        }
        [array]$allIssueData += $issueData
    }

    if ($allIssueData.severity -contains 'high') {
        $level = 'error'
    } elseif ($allIssueData.severity -contains 'medium') {
        $level = 'warning'
    } elseif ($allIssueData.severity -contains 'low') {
        $level = 'note'
    }
    
    Add-Type -AssemblyName System.Web
    $table = [System.Web.HttpUtility]::HtmlDecode(($allIssueData | Select-Object -Property * -ExcludeProperty labels, language, title, id, objFrom, Description | Sort-Object -Property 'CVSS Score' -Descending | ConvertTo-Html -Fragment)) | Out-String
    [array]$uniqueDescriptions = $allissueData.Description | Select-Object -Unique 
    [string]$details = $uniqueDescriptions -join "$([Environment]::NewLine; [Environment]::NewLine)---$([Environment]::NewLine; [Environment]::NewLine)" | Out-String
    [string]$markdown = "All of the vulnerabilities are listed below

$table"
    [array]$rules += [PSCustomObject]@{
        id = "vulnerable-$($package.packageName)-$($package.packageVersion)"
        name = (Get-Culture).TextInfo.ToTitleCase("Vulnerable $($package.packageName.Replace('-', ' '))") -Replace ' '
        helpUri = "https://security.snyk.io/vuln/$($package.id)"
        shortDescription = [PSCustomObject]@{
            text = "$($package.packageName) $($package.packageVersion) is vulnerable but does not have an upgrade path"
        }
        fullDescription = [PSCustomObject]@{
            text = "$($package.packageName) $($package.packageVersion) contains $($allIssueData.count) issues"
        }
        help = [PSCustomObject]@{
            text = ''
            markdown = "$markdown"
        }
        defaultConfiguration = [PSCustomObject]@{
            level = $level
        }
        properties = [PSCustomObject]@{
            tag = @('snyk', 'source composition analysis', 'security')
        }
    }
    $locations = [PSCustomObject]@{
        physicalLocation = [PSCustomObject]@{
            artifactLocation = [PSCustomObject]@{
                uri = "$pathToDependencyFile"
            }
            region = [PSCustomObject]@{
                startLine = $package.startLine
                endLine = $package.endLine
                startColumn = $package.startColumn
                endColumn = $package.endColumn
            }
        }
    }
    [array] $results += [PSCustomObject]@{
        ruleId = "vulnerable-$($package.packageName)-$($package.packageVersion)"
        message = [PSCustomObject]@{
            text = "Update $($package.packageName) $($package.packageVersion)"
        }
        locations = @($locations)
    } 
}

$rulesGroup = $rules | Group-Object -Property id
$rulesGroup | ForEach-Object {[array]$uniqueRules += $_.Group | Select-Object -First 1}
$tool = [PSCustomObject]@{
    tool = [PSCustomObject]@{
        driver = [PSCustomObject]@{
            name = 'Snyk Open Source'
            version = '1.0.0'
            rules = $uniqueRules
            informationUri = 'https://docs.snyk.io/products/snyk-open-source'
        }
    }
    results = $results
}
$sarif = [PSCustomObject]@{
    '$schema' = 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json'
    version = '2.1.0'
    runs = @($tool)
}
$sarif | ConvertTo-Json -Depth 100 | Out-File snyk.sarif