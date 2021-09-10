[CmdletBinding()]
Param
(
    [Parameter(Mandatory = $True)] [string] $dotSourceFilePath,    
    [Parameter(Mandatory = $True)]  [string]$snykApiKey,
    [Parameter(Mandatory = $True)]  [string]$snykOrgId,
    [Parameter(Mandatory = $True)]  [string]$integrationId,
    [Parameter(Mandatory = $True)]  [string]$repository,
    [Parameter(Mandatory = $True)]  [string]$branchName,
    [Parameter(Mandatory = $False)] [string]$projectOwnerEmailAddress
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
$repositoryName = $repository.Split('/')[-1]
$repositoryOwner = $repository.Split('/')[0]
[array]$currentSnykProjects = Get-SnykProjects -apiKey $snykApiKey -orgId $snykOrgId 
$splat = @{
    apiKey = $snykApiKey 
    orgId = $snykOrgId 
    integrationId = $integrationId 
    repositoryName = $repositoryName 
    repositoryOwner = $repositoryOwner
    branchName = $branchName
}
if ($null -eq $currentSnykProjects.name) {
    Import-SnykProject @splat | Out-Null
} elseif (($currentSnykProjects.name | ForEach-Object {$_.split(':')[0]}) -notcontains "$repositoryOwner/$repositoryName") {
    Import-SnykProject @splat | Out-Null
} else {
    Write-Output "Snyk project currently exists for $repositoryOwner/$repositoryName in Snyk organization, $snykOrgId."    
}
