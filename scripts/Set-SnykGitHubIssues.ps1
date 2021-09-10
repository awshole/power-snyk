[CmdletBinding()]
Param
(
    [Parameter(Mandatory = $True)] [string] $dotSourceFilePath,    
    [Parameter(Mandatory = $True)] [string] $pathToSnykIssues,
    [Parameter(Mandatory = $True)] [string] $gitHubToken,
    [Parameter(Mandatory = $True)] [string] $repository,
    [Parameter(Mandatory = $True)] [string] $branchName,
    [Parameter(Mandatory = $True)] [string] $pathToDependencyFile,
    [Parameter(Mandatory = $False)] [string] $githubIssueAssignee,
    [Parameter(Mandatory = $False)] [array] $licenseLabels,
    [Parameter(Mandatory = $False)] [array] $securityLabels,
    [Parameter(Mandatory = $False)] [array] $runId
)

function Get-GitHubRepositoryFileContent {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $True)] [string] $gitHubRepository,
        [Parameter(Mandatory = $True)] [string] $path,
        [Parameter(Mandatory = $True)] [string] $branch,
        [Parameter(Mandatory = $False)] [string] $gitHubToken
    )

    $uri = "https://api.github.com/repos/$gitHubRepository/contents/$path`?ref=$branch" # Need to escape the ? that indicates an http query
    $uri = [uri]::EscapeUriString($uri)
    if ($PSBoundParameters.ContainsKey('gitHubtoken')) {
        $base64Token = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$($gitHubToken)"))
        $headers = @{'Authorization' = "Basic $base64Token"}
        $splat = @{
            Method = 'Get'
            Uri = $uri
            Headers = $headers
            ContentType = 'application/json'
        }
    } else {
        $splat = @{
            Method = 'Get'
            Uri = $uri
            ContentType = 'application/json'
        }
    } 
    
    try {
        Invoke-RestMethod @splat
    } catch {
        Write-Warning "Unable to get file content."   
        $ErrorMessage = $_.Exception.Message
        Write-Warning "$ErrorMessage"
        break
    }
}


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

# Dot source GitHub Functions
$dotSourceFilePath = 'functions/github-rest-api-functions.ps1'
$splat = @{
    gitHubToken = $gitHubToken
    gitHubRepository = 'awshole/git-power'
    path = $dotSourceFilePath
    branch = 'main'
}

$dotSourceFileData = Get-GitHubRepositoryFileContent @splat
[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($dotSourceFileData.content)) | Out-File -FilePath $dotSourceFilePath.Split('/')[-1] -Force
$dotSourceFile = Get-Item -Path $dotSourceFilePath.Split('/')[-1]

if (Test-Path -Path $dotSourceFilePath.Split('/')[-1]) {
    try {
        . $dotSourceFile.FullName
        Remove-Item -Path $dotSourceFilePath.Split('/')[-1] -Recurse -Force
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

$repositoryName = $repository.Split('/')[-1]
$repositoryOwner = $repository.Split('/')[0]
$projectIssuesHash = Get-Content -Path $pathToSnykIssues | ConvertFrom-Json -AsHashTable
$issues = $projectIssuesHash.'vulnerabilities'
[array]$upgradableIssues = $issues | Where-Object {($_.upgradePath.Count -gt 0 -or $_.patches.Count -gt 0 -or $_.fixedIn.Count -gt 0)}
[array]$allUpgradablePackages = $upgradableIssues | ForEach-Object {$_.from[1]} | Select-Object -Unique
[array]$nonUpgradableIssues = $issues | Where-Object {($_.upgradePath.Count -eq 0) -and ($_.type -notlike 'license') -and ($_.patches.Count -eq 0) -and ($_.fixedIn.Count -eq 0)}
[array]$allNonUpgradablePackages = $nonUpgradableIssues | ForEach-Object {$_.from[1]} | Select-Object -Unique
[array]$licenseIssues = $issues | Where-Object {$_.type -like 'license'} | Group-Object -Property license

foreach ($package in $allUpgradablePackages) {
    $packageName = $package | Select-String -Pattern '.*(?=\@)' | ForEach-Object { $_.Matches[0].Value }
    $packageVersion = $package.Split('@')[-1].Trim()
    [array]$upgradablePackages += [PSCustomObject]@{
        packageName = $packageName
        packageVersion = $packageVersion
    }
}

foreach ($package in $allNonUpgradablePackages) {
    $packageName = $package | Select-String -Pattern '.*(?=\@)' | ForEach-Object { $_.Matches[0].Value }
    $packageVersion = $package.Split('@')[-1].Trim()
    $pattern = "$packageName[^-_].*\d"
    [array]$nonUpgradablePackages += [PSCustomObject]@{
        packageName = $packageName
        packageVersion = $packageVersion
    }
}

foreach ($issue in $licenseIssues) {
    $allIssueData = $null               
    foreach ($item in $issue.Group) {
        $issueData = [PSCustomObject][ordered]@{
            'Package Name' = $item.name
            id = $item.id
            Description = $item.description
            Version = $item.version
            title = "$($item.title)"
            Severity = $item.severity
            Url = $($item.licenseTemplateUrl)
            language = $item.language
            'From' = $item.from -join ' 🠆 ' | Out-String
            objFrom = $item.from
        }
        
        [array]$allIssueData += $issueData
    }
    
    Add-Type -AssemblyName System.Web
    $table = [System.Web.HttpUtility]::HtmlDecode(($allIssueData | Select-Object -Property * -ExcludeProperty id, Description, title, language, Url, objFrom | ConvertTo-Html -Fragment))
    $licenseDescription = $licenseDescription + "<details> <summary> $($issue.Name) license </summary>

### Additional Details
[$($issue.Name) license]($($allIssueData.Url | Select-Object -Unique)) has been identified as having issues. All of the occurances of the license are listed below." + "`r`n$table

</details>

"    
}

foreach ($package in $upgradablePackages) {
    $allIssueData = $null
    [array]$remediatedIssues = $upgradableIssues | Where-Object {$_.from -contains "$($package.packageName)@$($package.packageVersion)"}  
    foreach ($issue in $remediatedIssues) {       
        [array]$allIssueData += [PSCustomObject][ordered]@{
            'Vulnerable Package' = $issue.name
            id = $issue.id
            Description = $issue.description
            Version = $issue.version
            title = $issue.title
            Severity = $issue.severity
            'Exploit Maturity' = $issue.exploit
            CVE = "<a href=`"https://cve.mitre.org/cgi-bin/cvename.cgi?name=$($issue.identifiers.CVE)`">$($issue.title)</a>"
            'CVSS Score' = $issue.cvssScore
            language = $issue.language
            'From' = $issue.from -join ' &#8594; ' | Out-String
            objFrom = $issue.from
            'Fixed In' = $issue.fixedIn -join ', ' | Out-String
        }
    }
    $allIssueData = $allIssueData | Group-Object -Property id
    $uniqueIssueData = $null
    foreach ($issue in $allIssueData) {
        $from = $issue.Group.from -join '; '
        $toAdd = $issue.Group | Select-Object -First 1
        $toAdd.from = $from
        [array]$uniqueIssueData += $toAdd
    }
    if ($package.packageName -notlike '') {
        Add-Type -AssemblyName System.Web
        $table = [System.Web.HttpUtility]::HtmlDecode(($uniqueIssueData | Select-Object -Property * -ExcludeProperty labels, language, id, objFrom, Description | Sort-Object -Property 'CVSS Score' -Descending | ConvertTo-Html -Fragment))
        [array]$uniqueDescriptions = $uniqueIssueData.Description | Select-Object -Unique 
        [string]$details = $uniqueDescriptions -join "$([Environment]::NewLine; [Environment]::NewLine)---$([Environment]::NewLine; [Environment]::NewLine)" | Out-String
        [string]$markdown = "All of the vulnerabilities are listed below" + "`r`n$table" 
        $upgradablePackageDescription = $upgradablePackageDescription + "<details> <summary>$($package.packageName) $($package.packageVersion)</summary> 
 
## Additional Details

$($markdown | Out-String)

<details> <summary>Detailed remediation guidance

</summary>

$details 

</details>
  
---

</details>

"
    }
}

foreach ($package in $nonUpgradablePackages) {
    $allIssueData = $null
    [array]$unfixableIssues = $nonUpgradableIssues | Where-Object {$_.from -contains "$($package.packageName)@$($package.packageVersion)"}
    foreach ($issue in $unfixableIssues) {       
        [array]$allIssueData += [PSCustomObject][ordered]@{
            'Vulnerable Package' = $issue.name
            id = $issue.id
            Description = $issue.description
            Version = $issue.version
            title = "$($issue.title)"
            Severity = $issue.severity
            'Exploit Maturity' = $issue.exploit
            CVE = "<a href='https://cve.mitre.org/cgi-bin/cvename.cgi?name=$($issue.identifiers.CVE)'>$($issue.title)</a>"
            'CVSS Score' = $issue.cvssScore
            language = $issue.language
            'From' = $issue.from -join ' &#8594; ' | Out-String
            objFrom = $issue.from
        }
    }
    $allIssueData = $allIssueData | Group-Object -Property id
    $uniqueIssueData = $null
    foreach ($issue in $allIssueData) {
        $from = $issue.Group.from -join '; '
        $toAdd = $issue.Group | Select-Object -First 1
        $toAdd.from = $from
        [array]$uniqueIssueData += $toAdd
    }
    if ($package.packageName -notlike '') {
        Add-Type -AssemblyName System.Web
        $table = [System.Web.HttpUtility]::HtmlDecode(($uniqueIssueData | Select-Object -Property * -ExcludeProperty labels, language, id, objFrom, Description | Sort-Object -Property 'CVSS Score' -Descending | ConvertTo-Html -Fragment))
        [array]$uniqueDescriptions = $uniqueIssueData.Description | Select-Object -Unique 
        [string]$details = $uniqueDescriptions -join "$([Environment]::NewLine; [Environment]::NewLine)---$([Environment]::NewLine; [Environment]::NewLine)" | Out-String
        [string]$markdown = "All of the vulnerabilities are listed below" + "`r`n$table" 
        $nonUpgradablePackageDescription = $nonUpgradablePackageDescription + "<details> <summary>$($package.packageName) $($package.packageVersion)</summary> 
 
## Additional Details

$($markdown | Out-String)

<details> <summary>Detailed remediation guidance

</summary>

$details  

</details>

---

</details>

"
    }
}

if ($licenseIssues.Count -gt 0) {
    $description = "### License Issues
The following licenses were identified as having issues:

$licenseDescription

"
} 
if ($upgradablePackages.Count -gt 0) {
    $description = $description + "### Upgradeable Vulnerable Packages
The following packages were identified as having vulnerabilities that can be remediated:

$upgradablePackageDescription

"    
}
if ($nonUpgradablePackages.Count -gt 0) {
    $description = $description + "### Non-Upgradeable Vulnerable Packages
The following packages were identified as having vulnerabilities that **cannot** be remediated:


$nonUpgradablePackageDescription

" 
    
}
if ($licenseIssues.Count -gt 0 -or $upgradablePackages.Count -gt 0 -or $nonUpgradablePackages.Count -gt 0) {
    $issueContent = "## Overview 

Snyk Open Source allows you to easily find, prioritize and fix vulnerabilities in the open source libraries used in your cloud native applications. 

## Summary of results
$description"
}

$splat = @{
    gitHubToken = $gitHubToken
    gitHubRepositoryOwner = $repositoryOwner
    gitHubRepositoryName = $repositoryName
}

if ($null -eq $issueContent){
    Write-Output "No Snyk issues were encountered. No GitHub Issue to post."
    break
}
$currentGitHubIssues = Get-GitHubIssues @splat
$title = "[Snyk] Scan results for dependency file $pathToDependencyFile on branch $($branchName.Split('/')[-1])."
if ($currentGitHubIssues.title -contains $title) {
    $currentGitHubIssue = $currentGitHubIssues | Where-Object {$_.title -eq $title -and $_.state -like 'open'}
    Write-Output "Updating GitHub Issue."
    $splat = @{
        gitHubToken = $gitHubToken 
        gitHubRepositoryOwner = $repositoryOwner 
        gitHubRepositoryName = $repositoryName 
        issueContent = "$issueContent" 
        issueNumber = $currentGitHubIssue.number
    }
    $issue = Update-GitHubIssue @splat | Out-Null
    if ($null -ne $runId) {
        $content = "A [subsequent scan](https://github.com/$repositoryOwner/$repositoryName/actions/runs/$runId) was executed."
        Write-Output "Commenting on issue."
        $splat = @{
            gitHubToken = $gitHubToken 
            gitHubRepositoryOwner = $repositoryOwner 
            gitHubRepositoryName = $repositoryName
            issueNumber = $currentGitHubIssue.number
            content = $content
        }
        New-GitHubIssueComment @splat | Out-Null
    }
} else {
    Write-Output "Creating GitHub Issue."
    $splat = @{
        gitHubToken = $gitHubToken 
        gitHubRepositoryOwner = $repositoryOwner 
        gitHubRepositoryName = $repositoryName 
        title = "$title" 
        issueContent = "$issueContent" 
    }
    if ($PSBoundParameters.ContainsKey('githubIssueAssignee')) {
        $splat.Add('assignee', "$githubIssueAssignee")
    }
    $issue = New-GitHubIssue @splat
    if ($PSBoundParameters.ContainsKey('securityLabels') -and ($upgradablePackages.Count -gt 0 -or $nonUpgradablePackages.Count -gt 0)) {
        [array]$labels = $securityLabels   
        $splat = @{
            gitHubToken = $gitHubToken 
            gitHubRepositoryOwner = $repositoryOwner 
            gitHubRepositoryName = $repositoryName
            issueNumber = $issue.number 
            labels = $labels
        }
        New-GitHubIssueLabel @splat | Out-Null
    }
    if ($PSBoundParameters.ContainsKey('licenseLabels') -and $licenseIssues.Count -gt 0) {
        [array]$labels = $licenseLabels   
        $splat = @{
            gitHubToken = $gitHubToken 
            gitHubRepositoryOwner = $repositoryOwner 
            gitHubRepositoryName = $repositoryName
            issueNumber = $issue.number 
            labels = $labels
        }
        New-GitHubIssueLabel @splat | Out-Null
    }
}
