function Get-SnykAuditData {    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $True)] [string] $apiKey,
        [Parameter(Mandatory = $True)] [string] $orgId,
        [Parameter(Mandatory = $True)] [string] $from,
        [Parameter(Mandatory = $True)] [string] $to
    )

    $uri = "https://snyk.io/api/v1/org/$orgId/audit?from=$from&to=$to&page=1"
    $headers = @{'Authorization' = "token $apiKey"}
    try {
        Write-Verbose "Getting Snyk audit log data from $from to $to for organization, $orgId."
        $splat = @{
            Method = 'Post'
            Uri = $uri
            ContentType = 'application/json' 
            Headers = $headers
        }
        Invoke-RestMethod @splat
        Write-Verbose "Got Snyk audit log data from $from to $to for organization, $orgId."
    } catch {
        Write-Warning "Unable to get Snyk audit log data from $from to $to for organization, $orgId."
        $ErrorMessage = $_.Exception.Message
        Write-Warning "$ErrorMessage"
    } 
}

function Import-SnykProject {   
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $True)] [string] $apiKey,
        [Parameter(Mandatory = $True)] [string] $orgId,
        [Parameter(Mandatory = $True)] [string] $integrationId,
        [Parameter(Mandatory = $True)] [string] $repositoryName,
        [Parameter(Mandatory = $True)] [string] $repositoryOwner,
        [Parameter(Mandatory = $True)] [string] $branchName
    )
    
    $uri = "https://snyk.io/api/v1/org/$orgId/integrations/$integrationId/import"
    $headers = @{'Authorization' = "token $apiKey"}
    $body = @{
        target = @{
            owner = $repositoryOwner
            name = $repositoryName
            branch = $branchName
        }
    }
    try {
        Write-Verbose "Importing project into Snyk."
        $splat = @{
            Method = 'Post'
            Uri = $uri 
            ContentType = 'application/json' 
            Headers = $headers 
            Body = ($body | ConvertTo-Json)
        }
        Invoke-RestMethod @splat
        Write-Verbose "Imported project into Snyk."
    } catch {
        Write-Warning "Unable to import project into Snyk."
        $ErrorMessage = $_.Exception.Message
        Write-Warning "$ErrorMessage"
    }    
}

function Set-SnykProjectOwner {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $True)] [string] $apiKey,
        [Parameter(Mandatory = $True)] [string] $orgId,
        [Parameter(Mandatory = $True)] [string] $repositoryName,
        [Parameter(Mandatory = $True)] [string] $projectOwnerEmailAddress
    )
    
    $headers = @{'Authorization' = "token $apiKey"}
    try {
        Write-Verbose "Getting all projects."
        $uri = "https://snyk.io/api/v1/org/$orgId/projects"
        $splat = @{
            Method = 'Get' 
            Uri = $uri 
            ContentType = 'application/json' 
            Headers = $headers
        }
        $projects = (Invoke-RestMethod @splat).projects
        Write-Verbose "Got all projects."
    } catch {
        Write-Warning "Unable to get all projects."
        $ErrorMessage = $_.Exception.Message
        Write-Warning "$ErrorMessage"
        break
    }

    try {
        Write-Verbose "Getting all users."
        $uri = "https://snyk.io/api/v1/org/$orgId/members?includeGroupAdmins=true"
        $splat = @{
            Method = 'Get' 
            Uri = $uri 
            ContentType = 'application/json' 
            Headers = $headers
        }
        $users = Invoke-RestMethod @splat
        Write-Verbose "Got all users."
    } catch {
        Write-Warning "Unable to get all users."
        $ErrorMessage = $_.Exception.Message
        Write-Warning "$ErrorMessage"
        break
    }

    $projectId = ($projects | Where-Object {$_.name -like "*$repositoryName*"}).id | Select-Object -Unique
    $id = ($users | Where-Object {$_.email -like $projectOwnerEmailAddress}).id
    if ($null -ne $projectId -and $null -ne $id) {
        try {
            Write-Verbose "Setting Snyk project owner."
            $body = @{
                owner = @{
                    id = $id
                }
            }
            $uri = "https://snyk.io/api/v1/org/$orgId/project/$projectId"
            $splat = @{
                Method = 'Put' 
                Uri = $uri 
                ContentType = 'application/json' 
                Headers = $headers
                Body = ($body | ConvertTo-Json)
            }
            Invoke-RestMethod @splat
            Write-Verbose "Set Snyk project owner."
        } catch {
            Write-Warning "Unable to set Snyk project owner."
            $ErrorMessage = $_.Exception.Message
            Write-Warning "$ErrorMessage"
        }    
    }
}

function Get-SnykProjectIssues {   
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $True)] [string] $apiKey,
        [Parameter(Mandatory = $True)] [string] $orgId,
        [Parameter(Mandatory = $True)] [string] $repositoryName
    )

    $headers = @{'Authorization' = "token $apiKey"}  
    [array]$projectIds = (Get-SnykProjects -apiKey $apiKey -orgId $orgId | Where-Object {$_.name -like "*$repositoryName*"}).id | Select-Object -Unique
    foreach ($projectId in $projectIds) {
        try {
            Write-Verbose "Getting issues for project $projectId."
            $uri = "https://snyk.io/api/v1/org/$orgId/project/$projectId/aggregated-issues"
            $splat = @{
                Method = 'Post' 
                Uri = $uri 
                ContentType = 'application/json' 
                Headers = $headers 
            }
            $issue = Invoke-RestMethod @splat
            $issue | Add-Member -MemberType noteproperty -Name 'projectId' -Value $projectId
            [array]$issues += $issue
            Write-Verbose "Got all issues for project $projectId."
        } catch {
            Write-Warning "Unable to get all issues for project $projectId."
            $ErrorMessage = $_.Exception.Message
            Write-Warning "$ErrorMessage"
        }
    }
    $issues    
}

function Get-SnykProjects {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $True)] [string] $apiKey,
        [Parameter(Mandatory = $True)] [string] $orgId
    )
    
    $headers = @{'Authorization' = "token $apiKey"}
    try {
        Write-Verbose "Getting all projects."
        $uri = "https://snyk.io/api/v1/org/$orgId/projects"
        $splat = @{
            Method = 'Get'
            Uri = $uri 
            ContentType = 'application/json'
            Headers = $headers
        }
        (Invoke-RestMethod @splat).projects
        Write-Verbose "Got all projects."
    } catch {
        Write-Warning "Unable to get all projects."
        $ErrorMessage = $_.Exception.Message
        Write-Warning "$ErrorMessage"
    }
}

function Get-SnykOrganizationIntegrations {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $True)] [string] $apiKey,
        [Parameter(Mandatory = $True)] [string] $orgId
    )
    
    $headers = @{'Authorization' = "token $apiKey"}
    try {
        Write-Verbose "Getting all projects."
        $uri = "https://snyk.io/api/v1/org/$orgId/integrations"
        $splat = @{
            Method = 'Get'
            Uri = $uri 
            ContentType = 'application/json'
            Headers = $headers
        }
        Invoke-RestMethod @splat
        Write-Verbose "Got all projects."
    } catch {
        Write-Warning "Unable to get all projects."
        $ErrorMessage = $_.Exception.Message
        Write-Warning "$ErrorMessage"
    }
}

function Get-SnykOrganizations {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $True)] [string] $apiKey    
    )
    
    $headers = @{'Authorization' = "token $apiKey"}
    try {
        Write-Verbose "Getting all organizations."
        $uri = "https://snyk.io/api/v1/orgs"
        $splat = @{
            Method = 'Get'
            Uri = $uri 
            ContentType = 'application/json'
            Headers = $headers
        }
        (Invoke-RestMethod @splat).orgs
        Write-Verbose "Got all organizations."
    } catch {
        Write-Warning "Unable to get all Snyk organizations."
        $ErrorMessage = $_.Exception.Message
        Write-Warning "$ErrorMessage"
    }
}

function Remove-SnykProject {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $True)] [string] $apiKey,    
        [Parameter(Mandatory = $True)] [string] $organizationId,
        [Parameter(Mandatory = $True)] [string] $repositoryName    
    )
    
    $headers = @{'Authorization' = "token $apiKey"}
    try {
        Write-Verbose "Getting all projects."
        $uri = "https://snyk.io/api/v1/org/$organizationId/projects"
        $splat = @{
            Method = 'Get'
            Uri = $uri 
            ContentType = 'application/json'
            Headers = $headers
        }
        $projects = (Invoke-RestMethod @splat).projects
        Write-Verbose "Got all projects."
    } catch {
        Write-Warning "Unable to get all projects."
        $ErrorMessage = $_.Exception.Message
        Write-Warning "$ErrorMessage"
    }

    $projectIds = ($projects | Where-Object {$_.name.Split(':')[0] -like "*$repositoryName*"}).id
    foreach ($projectId in $projectIds) {
        try {
            Write-Verbose "Removing project $projectId."
            $uri = "https://snyk.io/api/v1/org/$organizationId/project/$projectId"
            $splat = @{
                Method = 'Delete'
                Uri = $uri 
                ContentType = 'application/json'
                Headers = $headers
            }
            Invoke-RestMethod @splat
            Write-Verbose "Removed project $projectId."
        } catch {
            Write-Warning "Unable to remove project $projectId."
            $ErrorMessage = $_.Exception.Message
            Write-Warning "$ErrorMessage"
        }    
    }
}

function Get-SnykCurrentIssues {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $True)] [string] $apiKey    
    )
    
    $headers = @{'Authorization' = "token $apiKey"}
    try {
        Write-Verbose "Getting all Snyk issues."
        $page = 1
        do {
            $uri = "https://snyk.io/api/v1/reporting/issues/latest?page=$page&perPage=1000"
            [array]$snykOrganizations = Get-SnykOrganizations -apiKey $apiKey
            $body = [PSCustomObject]@{
                filters = @{
                    orgs = @($snykOrganizations.id)
                }
            }
            $splat = @{
                Method = 'Post'
                Uri = $uri
                ContentType = 'application/json'
                Body = ($body | ConvertTo-Json -Depth 100)
                Headers = $headers
            }
            [array]$results = Invoke-RestMethod @splat
            [array]$currentIssues += $results.results
            $page++ 
        } until ($results.results.count -lt 1000)
        Write-Verbose "Got all Snyk issues."
    } catch {
        Write-Warning "Unable to get all Snyk issues."
        $ErrorMessage = $_.Exception.Message
        Write-Warning "$ErrorMessage"
    }
    $currentIssues
}
