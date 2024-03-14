Function New-STIGChecklist {
    [cmdletbinding()]
    param (
        # Type of STIG Checklist, e.g. OS, .NetFramework, Defender, etc.
        [Parameter(Position=0, Mandatory=$true)]
        [string]$Type,
        [Parameter(Position=1, Mandatory=$true)]
        [string]$Format
    )
    New-STIG_Folder
    Move-SCAPResults
    if ($Format -eq "xml"){
        New-XMLSTIGChecklist -Type $Type
    }
    elseif ($Format -eq "json"){
        New-JSONSTIGChecklist -Type $Type
    }
}
Export-ModuleMember -Function New-STIGChecklist

Function New-STIG_Folder{
    $Data_Drive = (Get-Volume | Where-Object DriveLetter -ne $null).DriveLetter -ne "C"
    $Test_Path = Test-Path "$($Data_Drive):\STIG_AUTOMATION"
    if ($Test_Path -eq $false){
        New-Item -Path "$($Data_Drive):\STIG_AUTOMATION\" -Name "Blank_Checklists" -ItemType Directory
        New-Item -Path "$($Data_Drive):\STIG_AUTOMATION\" -Name "Completed_Checklists" -ItemType Directory
        New-Item -Path "$($Data_Drive):\STIG_AUTOMATION\" -Name "SCAP_Results" -ItemType Directory
    }
}

Function Move-SCAPResults {
    $Data_Drive = (Get-Volume | Where-Object DriveLetter -ne $null).DriveLetter -ne "C"
    $Date = Get-Date -Format yyyy-MM-dd
    $SCAP_Folder_Name = (Get-ChildItem -Path "$env:USERPROFILE\SCC\Sessions\" | Where-Object Name -Like "$Date*").Name
    gpresult /h "$($Data_Drive):\STIG_AUTOMATION\gpresult.html"

    if ($null -eq (Get-ChildItem "$($Data_Drive):\STIG_AUTOMATION\SCAP_Results").Name){
        Move-Item "$env:USERPROFILE\SCC\Sessions\$SCAP_Folder_Name\Results\SCAP\XML\*" -Destination "$($Data_Drive):\STIG_AUTOMATION\SCAP_Results\"
    
    }
    elseif ((Get-ChildItem "$($Data_Drive):\STIG_AUTOMATION\SCAP_Results").Name[-1].Contains($Date) -ne $true){
        Remove-Item "$($Data_Drive):\STIG_Automation\SCAP_Results\*"
        Move-Item "$env:USERPROFILE\SCC\Sessions\$SCAP_Folder_Name\Results\SCAP\XML\*" -Destination "$($Data_Drive):\STIG_AUTOMATION\SCAP_Results\"
        Remove-Item "$env:USERPROFILE\SCC\Sessions\$SCAP_Folder_Name" -Recurse
    }   
}

Function New-XMLSTIGChecklist {
    Write-Host "HelloWorld"
} 

Function New-JSONSTIGChecklist {
    [cmdletbinding()]
    param(
        [Parameter(Position=0, Mandatory=$true)]
        [string]$Type
    )
    $Checklist = Read-BlankJSONChecklist -Type $Type
    $Checklist = Update-JSONChecklist_SCAP_Results -Checklist $Checklist -Type $Type
    Update-JSONChecklist_Manual_Checks -Checklist $Checklist -Type $Type
}
Export-ModuleMember -Function New-JSONSTIGChecklist

Function Update-JSONChecklist_SCAP_Results {
    [cmdletbinding()]
    param(
        [Parameter(Position=0, Mandatory=$true)]
        $Checklist,
        [Parameter(Position=1, Mandatory=$true)]
        [string]$Type
    )
    $UserName                              = (Get-ADUser $env:USERNAME).Name
    $SCAP_Info                             = Get-XCCDF_Info -Type $Type
    $SCAP_Tool                             = $SCAP_Info.XCCDF.ChildNodes.TestResult.'test-system'
    $SCAP_Time                             = $SCAP_Info.XCCDF.ChildNodes.TestResult.'end-time'
    $Checklist.target_data.host_name       = $SCAP_Info.Name
    $Checklist.target_data.fqdn            = $SCAP_Info.FQDN
    $Checklist.target_data.ip_address      = $SCAP_Info.IP
    $Checklist.target_data.mac_address     = $SCAP_Info.MAC
    $Checklist.target_data.role            = "Member Server"
    $Checklist.target_data.technology_area = "Windows OS"

    $Status = [ordered]@{
        Pass = [ordered]@{
            Result  = "not_a_finding"
            Comment = "THIS IS NOT A FINDING."
        }
        Fail = [ordered]@{
            Result  = "open"
            Comment = "THIS IS A FINDING."
        }
        NotApplicable = [ordered]@{
            Result  = 'not_applicable'
            Comment = "THIS IS NOT APPLICABLE."
        }
    }
    
    foreach ($Rule_ID in $Checklist.stigs.rules){
        if (($SCAP_Info.SCAP_Results).contains($Rule_ID.rule_id_src)){
            $Result                  = $SCAP_Info.SCAP_Results.($Rule_ID.rule_id_src).Result
            $Rule_ID.status          = $Status.$Result.Result
            $Rule_ID.finding_details = "Tool: $SCAP_Tool`nTime: $SCAP_Time`nResult: $Result"
            $Rule_ID.comments        = "$UserName completed a SCAP Scan on $SCAP_Time and the result was '$Result'. "
            $Rule_ID.comments        += $Status.$Result.Comment
        }
    }
    return $Checklist
}

Function Update-JSONChecklist_Manual_Checks{
    [cmdletbinding()]
    param(
        [Parameter(Position=0, Mandatory=$true)]
        $Checklist,
        [Parameter(Position=0, Mandatory=$true)]
        [string]$Type
    )
    if ($Type -eq "OS"){
        $Vulnerability_Checks    = Get-ManualChecks_OS -Checklist $Checklist
        $DomainController_Checks = Get-DomainController_Checks_NA
        $DC_Vulnerability_List   = (
            "V-254385", "V-254392", "V-254393", "V-254394", "V-254395", "V-254396", "V-254397",
            "V-254398", "V-254399", "V-254400", "V-254401", "V-254402", "V-254403", "V-254404",
            "V-254405", "V-254406", "V-254412", "V-254413", "V-254414", "V-254415")
    }
    elseif ($Type -eq "DotNetFramework"){
        $Vulnerability_Checks = Get-DotNetFramework_Manual_Checks -Checklist $Checklist
    }

    foreach ($Vulnerability_ID in $Checklist.stigs.rules){
        if (($Vulnerability_Checks).Contains($Vulnerability_ID.group_id)){
            $Vulnerability_ID.status          = $Vulnerability_Checks.($Vulnerability_ID.group_id).Status
            $Vulnerability_ID.comments        = $Vulnerability_Checks.($Vulnerability_ID.group_id).Comment
            $Vulnerability_ID.finding_details = $Vulnerability_Checks.($Vulnerability_ID.group_id).Finding_Details
        }
        elseif ($DC_Vulnerability_List.Contains($Vulnerability_ID.group_id)){
            $Vulnerability_ID.status          = $DomainController_Checks.Status
            $Vulnerability_ID.comments        = $DomainController_Checks.Comment
            $Vulnerability_ID.finding_details = $DomainController_Checks.Finding_Details
        }
    }
    $Checklist | ConvertTo-Json -Depth 4 | Out-File "D:\STIG_Automation\Completed_Checklists\$($env:COMPUTERNAME)_$($Checklist.stigs.stig_id).cklb"
}

Function Get-XCCDF_Info {
    [cmdletbinding()]
    param(
        [Parameter(Position=0, Mandatory=$true)]
        [string]$Type
    )
    $XCCDF = Read-XCCDF -Type $Type
    $XCCDF_Host_Info = $XCCDF.ChildNodes.TestResult.'target-facts'.fact
    $SCAP_Results = Get-SCAPResult -XML $XCCDF

    $Hash_Table = [ordered]@{
        Name         = ($XCCDF_Host_Info | Where-Object Name -Like *host_name).'#text'
        FQDN         = ($XCCDF_Host_Info | Where-Object Name -Like *fqdn).'#text'
        IP           = ($XCCDF_Host_Info | Where-Object Name -Like *ipv4).'#text'
        MAC          = ($XCCDF_Host_Info | Where-Object Name -Like *mac).'#text'
        XCCDF        = $XCCDF
        SCAP_Results = $SCAP_Results
    }
    return $Hash_Table
}
Export-ModuleMember -Function Get-XCCDF_Info

Function Get-SCAPResult {
    [cmdletbinding()]
    param(
        [Parameter(Position=0, Mandatory=$true)]
        $XML
    )
    foreach ($Vulnerability in $XML.ChildNodes.testResult.'rule-result'){
        $SCAP_Results += [ordered]@{
            $Vulnerability.idref.substring(15,31).substring(10,21) = [ordered]@{
                Result = $Vulnerability.result
            }
        }
    }
    return $SCAP_Results
}

Function Read-BlankJSONChecklist {
    [cmdletbinding()]
    param (
        [Parameter(Position=0, Mandatory=$true)]
        [string]
        $Type
    )
    $Path = (Get-Location).Path
    $Data_Drive = (Get-Volume | Where-Object DriveLetter -ne $null).DriveLetter -ne "C"
    $Data_Path = "$($Data_Drive):\STIG_Automation\Blank_Checklists"
    $Checklist = [ordered]@{
        OS              = "Blank*2022.cklb"
        DotNetFramework = "Blank*Framework.cklb"
    }
    try {
        $File = (Get-ChildItem -Path $Path -Recurse -Filter $Checklist.$Type -ErrorAction SilentlyContinue).Name

        if ($null -ne $File){
            return Get-Content $Path\$File -Encoding Ascii| ConvertFrom-Json
        }
        else {
            $File = (Get-ChildItem -Path $Data_Path -Recurse -Filter $Checklist.$Type).Name
            return Get-Content $Data_Path\$File | ConvertFrom-Json
        }
    }
    catch {
        Write-Warning "The Blank Checklist does not EXIST. Please place the blank CKLB file in your current working directory, or in D:\STIG_Automation\Blank_Checklists\.`n`n
        Ensure the Naming Convention is as follows:`n`n
        Blank_MS_Windows_Server_2016.cklb`nBlank_MS_Windows_Server_2019.cklb`nBlank_MS_Windows_Server_2022.cklb`nBlank_MS_Dot_Net_Framework.cklb"
        throw
    }
}
Export-ModuleMember -Function Read-BlankJSONChecklist

Function Read-XCCDF {
    [cmdletbinding()]
    param (
        [Parameter(Position=0, Mandatory=$true)]
        [string]
        $Type
    )
    $Path = (Get-Location).Path
    $Data_Path = "D:\STIG_Automation\SCAP_Results"
    $XCCDF = [ordered]@{
        OS              = "$($env:COMPUTERNAME)*XCCDF-Results_MS_Windows_Server*.xml"
        DotNetFramework = "$($env:COMPUTERNAME)*XCCDF-Results_MS_Dot_Net_Framework*.xml"
    }
    try {
        $File = (Get-ChildItem -Path $Path -Recurse -Filter $XCCDF.$Type -ErrorAction SilentlyContinue).Name

        if ($null -ne $File){
            return [xml]$Content = Get-Content $Path\$File
        }
        else {
            $File = (Get-ChildItem -Path $Data_Path -Recurse -Filter $XCCDF.$Type).Name
            return [xml]$Content = Get-Content $Data_Path\$File
        }
    }
    catch {
        Write-Warning "XCCDF file does not EXIST. Please place XCCDF file in your current working directory, or in D:\STIG_Automation\Scap_Results\."
        throw
    }
}

Function Get-ManualChecks_OS{
    [cmdletbinding()]
    param(
        [Parameter(Position=0, Mandatory=$true)]
        $Checklist
    )
    $ServersWithServiceAccounts = (INSERT SERVERS THAT USES SERVICE ACCOUNTS)
    $Data_Drive = (Get-Volume | Where-Object DriveLetter -ne $null).DriveLetter -ne "C"
    $gpresult = Get-Content "$($Data_Drive):\STIG_Automation\gpresult.html"
    $254238 = Get-V254238
    $254239 = Get-V254239
    $254240 = Get-V254240
    $254241 = Get-V254241
    $254242 = Get-V254242
    $254243 = Get-V254243 -List $ServersWithServiceAccounts
    $254244 = Get-V254244 -List $ServersWithServiceAccounts
    $254245 = Get-V254245
    $254246 = Get-V254246
    $254248 = Get-V254248
    $254249 = Get-V254249
    $254251 = Get-V254251
    $254252 = Get-V254252
    $254253 = Get-V254253
    $254254 = Get-V254254
    $254255 = Get-V254255
    $254256 = Get-V254256
    $254257 = Get-V254257
    $254258 = Get-V254258
    $254259 = Get-V254259
    $254260 = Get-V254260
    $254261 = Get-V254261
    $254262 = Get-V254262
    $254263 = Get-V254263
    $254264 = Get-V254264
    $254265 = Get-V254265
    $254266 = Get-V254266
    $254267 = Get-V254267
    $254268 = Get-V254268
    $254279 = Get-V254279
    $254280 = Get-V254280
    $254281 = Get-V254281
    $254282 = Get-V254282 -Info $gpresult
    #$254490 = Get-V254490
    $Vulnerability_Checks = [ordered]@{
        "V-254238" = [ordered]@{
            Status          = ($254238).Status
            Comment         = ($254238).Comment
            Finding_Details = ($254238).Finding_Details
        }
        "V-254239" = [ordered]@{
            Status          = ($254239).Status
            Comment         = ($254239).Comment
            Finding_Details = ($254239).Finding_Details
        }
        "V-254240" = [ordered]@{
            Status          = ($254240).Status
            Comment         = ($254240).Comment
            Finding_Details = ($254240).Finding_Details
        }
        "V-254241" = [ordered]@{
            Status          = ($254241).Status
            Comment         = ($254241).Comment
            Finding_Details = ($254241).Finding_Details
        }
        "V-254242" = [ordered]@{
            Status          = ($254242).Status
            Comment         = ($254242).Comment
            Finding_Details = ($254242).Finding_Details
        }
        "V-254243" = [ordered]@{
            Status          = ($254243).Status
            Comment         = ($254243).Comment
            Finding_Details = ($254243).Finding_Details
        }
        "V-254244" = [ordered]@{
            Status          = ($254244).Status
            Comment         = ($254244).Comment
            Finding_Details = ($254244).Finding_Details
        }
        "V-254245" = [ordered]@{
            Status          = ($254245).Status
            Comment         = ($254245).Comment
            Finding_Details = ($254245).Finding_Details
        }
        "V-254246" = [ordered]@{
            Status          = ($254246).Status
            Comment         = ($254246).Comment
            Finding_Details = ($254246).Finding_Details
        }
        "V-254248" = [ordered]@{
            Status          = ($254248).Status
            Comment         = ($254248).Comment
            Finding_Details = ($254248).Finding_Details
        }
        "V-254249" = [ordered]@{
            Status          = ($254249).Status
            Comment         = ($254249).Comment
            Finding_Details = ($254249).Finding_Details
        }
        "V-254251" = [ordered]@{
            Status          = ($254251).Status
            Comment         = ($254251).Comment
            Finding_Details = ($254251).Finding_Details
        }
        "V-254252" = [ordered]@{
            Status          = ($254252).Status
            Comment         = ($254252).Comment
            Finding_Details = ($254252).Finding_Details
        }
        "V-254253" = [ordered]@{
            Status          = ($254253).Status
            Comment         = ($254253).Comment
            Finding_Details = ($254253).Finding_Details
        }
        "V-254254" = [ordered]@{
            Status          = ($254254).Status
            Comment         = ($254254).Comment
            Finding_Details = ($254254).Finding_Details
        }
        "V-254255" = [ordered]@{
            Status          = ($254255).Status
            Comment         = ($254255).Comment
            Finding_Details = ($254255).Finding_Details
        }
        "V-254256" = [ordered]@{
            Status          = ($254256).Status
            Comment         = ($254256).Comment
            Finding_Details = ($254256).Finding_Details
        }
        "V-254257" = [ordered]@{
            Status          = ($254257).Status
            Comment         = ($254257).Comment
            Finding_Details = ($254257).Finding_Details
        }
        "V-254258" = [ordered]@{
            Status          = ($254258).Status
            Comment         = ($254258).Comment
            Finding_Details = ($254258).Finding_Details
        }
        "V-254259" = [ordered]@{
            Status          = ($254259).Status
            Comment         = ($254259).Comment
            Finding_Details = ($254259).Finding_Details
        }
        "V-254260" = [ordered]@{
            Status          = ($254260).Status
            Comment         = ($254260).Comment
            Finding_Details = ($254260).Finding_Details
        }
        "V-254261" = [ordered]@{
            Status          = ($254261).Status
            Comment         = ($254261).Comment
            Finding_Details = ($254261).Finding_Details
        }
        "V-254262" = [ordered]@{
            Status          = ($254262).Status
            Comment         = ($254262).Comment
            Finding_Details = ($254262).Finding_Details
        }
        "V-254263" = [ordered]@{
            Status          = ($254263).Status
            Comment         = ($254263).Comment
            Finding_Details = ($254263).Finding_Details
        }
        "V-254264" = [ordered]@{
            Status          = ($254264).Status
            Comment         = ($254264).Comment
            Finding_Details = ($254264).Finding_Details
        }
        "V-254265" = [ordered]@{
            Status          = ($254265).Status
            Comment         = ($254265).Comment
            Finding_Details = ($254265).Finding_Details
        }
        "V-254266" = [ordered]@{
            Status          = ($254266).Status
            Comment         = ($254266).Comment
            Finding_Details = ($254266).Finding_Details
        }
        "V-254267" = [ordered]@{
            Status          = ($254267).Status
            Comment         = ($254267).Comment
            Finding_Details = ($254267).Finding_Details
        }
        "V-254268" = [ordered]@{
            Status          = ($254268).Status
            Comment         = ($254268).Comment
            Finding_Details = ($254268).Finding_Details
        }
        "V-254279" = [ordered]@{
            Status          = ($254279).Status
            Comment         = ($254279).Comment
            Finding_Details = ($254279).Finding_Details
        }
        "V-254280" = [ordered]@{
            Status          = ($254280).Status
            Comment         = ($254280).Comment
            Finding_Details = ($254280).Finding_Details
        }
        "V-254281" = [ordered]@{
            Status          = ($254281).Status
            Comment         = ($254281).Comment
            Finding_Details = ($254281).Finding_Details
        }
        "V-254282" = [ordered]@{
            Status          = ($254282).Status
            Comment         = ($254282).Comment
            Finding_Details = ($254282).Finding_Details
        }
        # "V-254490" = [ordered]@{
        #     Status          = ($254490).Status
        #     Comment         = ($254490).Comment
        #     Finding_Details = ($254490).Finding_Details
        # }
        # Last Check due to how long it takes
        
    }
    return $Vulnerability_Checks
}
Export-ModuleMember -Function Get-OS_Manual_Checks

Function Get-FindingComment {
    $UserName = (Get-ADUser $env:USERNAME).Name
    $Comment = [ordered]@{
        not_a_finding  = "$UserName manually verified $env:COMPUTERNAME is compliant with this check. THIS IS NOT A FINDING."
        open           = "$UserName manually verified $env:COMPUTERNAME is NOT compliant with this check. THIS IS A FINDING."
        not_applicable = "$UserName manually verified this check does not apply to $env:COMPUTERNAME. THIS IS NOT APPLICABLE."
        not_reviewed   = "This Check needs to be validated."
    }
    return $Comment
}
Export-ModuleMember -Function Get-FindingComment

Function Get-DomainController_Checks_NA {
    $Result = [ordered]@{
        Status          = "not_applicable"
        Comment         = (Get-FindingComment).not_applicable
        Finding_Details = "$env:COMPUTERNAME is NOT A Domain Controller. $env:COMPUTERNAME is a Member Server/Application Server."
    }
    return $Result
}

Function Get-V254238{
    $Result = [ordered]@{
        Status = "not_a_finding"
        Comment = (Get-FindingComment).not_a_finding
        Finding_Details = "Users with Administrative access to $env:COMPUTERNAME require alternative administrator accounts utilizing DoD Issued Alt Tokens."
    }
    return $Result
}

Function Get-V254239{
    $Account = Get-LocalUser | Where-Object SID -like S-1-5-21*500
    $finding_details = '$Account = Get-LocalUser | Where-Object SID -like S-1-5-21*500' + "`n`n" + '$Account.Enabled' + "`n$($Account.Enabled)"
    $finding_details_enabled =  $finding_details + "`n`n" +'$Account.PasswordLastSet -lt $Account.PasswordLastSet.AddDays(60)' + 
    "`n$($Account.PasswordLastSet -lt $Account.PasswordLastset.AddDays(60))" + 
    "`n`nThe Local Administrator account is ENABLED. The password will need to be reset on/before $($Account.PasswordLastset.AddDays(60))"
    
    $Result = [ordered]@{
        True = [ordered]@{
            True = [ordered]@{
                Status          = "not_a_finding"
                Comment         = (Get-FindingComment).not_a_finding
                Finding_Details = "Validated the local administrator account, $($Account.Name), is enabled using the commands below:`n`n" + $finding_details_enabled
            }
            False = [ordered]@{
                Status          = "open"
                Comment         = (Get-FindingComment).open
                Finding_Details = "Validated the local administrator account, $($Account.Name), is enabled using the commands below:`n`n" + $finding_details_enabled
            }
        }
        False = [ordered]@{
            Status          = "not_applicable"
            Comment         = (Get-FindingComment).not_applicable
            Finding_Details = "Validated the local administrator account, $($Account.Name), is disabled using the commands below:`n`n" + $finding_details
        }
    }
    if ($Account.Enabled){
        if ($Account.PasswordLastSet -lt $Account.PasswordLastSet.AddDays(60)){
            return $Result.True.True
        }
        else {
            return $Result.True.False
        }
    }
    else {
        return $Result.False
    }
}

Function Get-V254240 {
    $Result = [ordered]@{
        Status          = "not_a_finding"
        Comment         = (Get-FindingComment).not_a_finding 
        Finding_Details = "Validated whitelisted applications are documented in our PPSM for AWS Servers." +
        "Access to web browsers via EOSS Windows Servers communicate only to internal EOSS Systems."
    }
    return $Result
}

Function Get-V254241 {
    $Backup_Operators = Get-LocalGroupMember -Group "Backup Operators"
    $Result = [ordered]@{
        0 = [ordered]@{
            Status          = "not_applicable"
            Comment         = (Get-FindingComment).not_applicable
            Finding_Details = "Validated there are no users or groups associated with the Backup Operators group." +
            " Validation completed by the command below.`n`n(Get-LocalGroupMember -Group 'Backup Operators').Length" +
            "`n$($Backup_Operators.Length)"
        }
        Populated = [ordered]@{
            Status          = "open"
            Comment         = (Get-FindingComment).open
            Finding_Details = "Verified there is no requirement for Backup Operators due to the Utilization of CommVault" +
            " Service. Please remove Users/Groups from Backup Operators Group.`n`nGet-LocalGroupMember -Group 'Backup" +
            " Operators'`n$Backup_Operators"
        }
    }
    if ($Backup_Operators.Length -eq 0){
        return $Result.0
    }
    else {
        return $Result.Populated
    }
}

Function Get-V254242 {
    $Result = [ordered]@{
        Status          = "not_a_finding"
        Comment         = (Get-FindingComment).not_a_finding
        Finding_Details = "Validated DHA has a password policy for manually managed application/service accounts that " +
        "require at least 15 characters and meet complexity rules."
    }
    return $Result
}

Function Get-V254243 {
    [cmdletbinding()]
    param(
        [Parameter(Position=0, Mandatory=$true)]
        $List
    )
    $SearchBase = "INSERT SEARCHBASE"   # Change to OU and Domain Search Base.
    $ServiceAccounts = Get-ADUser -SearchBase $SearchBase -Filter * -Properties PasswordLastSet
    
    if ($List.Contains($env:COMPUTERNAME) -eq $false){
        $pw_change_required = "Not_Required"
    }
    else {
        foreach ($ServiceAccount in $ServiceAccounts){
            if ($ServiceAccount.PasswordLastSet -lt ($ServiceAccount.PasswordLastSet).AddDays(365)){
                $pw_change_required = "False"
                $Account_Inputs += "`n`nName: $($ServiceAccount.Name)`nPasswordLastSet: $($ServiceAccount.PasswordLastSet)"
            }
            else {
                $pw_change_required = "True"
                $Account_Inputs += "`n`nName: $($ServiceAccount.Name)`nPasswordLastSet: $($ServiceAccount.PasswordLastSet)"
                break
            }
        }
    }
    
    $Result = [ordered]@{
        True = [ordered]@{
            Status = "open"
            Comment = (Get-FindingComment).open
            Finding_Details = "Validated a service account exceeds 365 days since" +
            "the last password change. See validations below.`n`nGet-ADUser -SearchBase " +
            "'INSERT SEARCH BASE' " +
            "-Filter * -Properties PasswordLastSet" + $Account_Inputs
        }
        False = [ordered]@{
            Status          = "not_a_finding"
            Comment         = (Get-FindingComment).not_a_finding
            Finding_Details = "Validated service accounts do not exceed 365 days since the last" +
            "password change. See validations below.`n`nGet-ADUser -SearchBase 'INSERT SEARCH," +
            "BASE' -Filter * -Properties PasswordLastSet" + $Account_Inputs
        }
        Not_Required = [ordered]@{
            Status          = "not_applicable"
            Comment         = (Get-FindingComment).not_applicable
            Finding_Details = "Validate $env:COMPUTERNAME does not utilize service accounts."
        }
    }
    return $Result.$pw_change_required
}

Function Get-V254244 {
    [cmdletbinding()]
    param(
        [Parameter(Position=0, Mandatory=$true)]
        $List
    )
    if ($List.Contains($env:COMPUTERNAME) -eq $false){
        $Required = "False"
    }
    else {
        $Required = "True"
    }
    $Result = [ordered]@{
        True = [ordered]@{
            Status          = "not_a_finding"
            Comment         = (Get-FindingComment).not_a_finding
            Finding_Details = "Validated $env:COMPUTERNAME utilizes shared accounts, e.g. service accounts." +
            "These are required for proper application functionality. Service Accounts are documented by ISSO." +
            "Only required Program Leadership, System Administrators (Service Account Maintainers), and Application" +
            " Administrators (Service Account Application Users) have access to the service account password."
        }
        False = [ordered]@{
            Status          = "not_applicable"
            Comment         = (Get-FindingComment).not_applicable
            Finding_Details = "Validated $env:COMPUTERNAME does not utilize shared accounts, e.g service accounts."
        }
    }
    return $Result.$Required
}

Function Get-V254245 {
    Get-AppLockerPolicy -Effective -XML | Out-File "D:\STIG_Automation\$env:COMPUTERNAME.xml"

    $Result = [ordered]@{
        Status          = 'not_a_finding'
        Comment         = (Get-FindingComment).not_a_finding
        Finding_Details = "Validated AppLocker Policies are in place for $env:COMPUTERNAME.`n`n" +
        "Get-AppLockerPolicy -Effective -XML | Out-File 'D:\STIG_Automation\$env:COMPUTERNAME.xml'" +
        "`n`nContent:`n$(Get-Content "D:\STIG_Automation\$env:COMPUTERNAME.xml")" 
    }
    return $Result
}

Function Get-V254246 {
    try {
        $TPM = Get-Tpm
        if ($TPM.TpmReady){
            $Status = 'not_a_finding'
        }
        else {
            $Status = 'open'
        }
        $Result = [ordered]@{
            Status = $Status
            Comment = (Get-FindingComment).$Status
            Finding_Details = "Validated TPM is present on $env:COMPUTERNAME using Get-Tpm.`n`nGet-Tpm`n$(Get-Tpm | Out-String)"
        }
        return $Result
    }
    catch {
        Write-Warning "TPM is NOT Present on $env:COMPUTERNAME."
    }
    $Result = [ordered]@{
        Status = 'open'
        Comment = (Get-FindingComment).open
        Finding_Details = "Validated TPM is NOT present on $env:COMPUTERNAME."
    }
    return $Result
}

Function Get-V254248 {
    $Services = Get-Service -Exclude "McpManagementService"
    
    if ($Services.Name.Contains("TrellixDLPAgentService")){
        $AnitVirus = $Services | Where-Object Name -eq TrellixDLPAgentService
        $Running = $AnitVirus.Status -eq "Running"
    }
    elseif ($Services.Name.Contains("WinDefend")){
        $AnitVirus = $Services | Where-Object Name -eq WinDefend
        $Running = $AnitVirus.Status -eq "Running"
    }
    else {
        $Status = "open"
        $finding_details = "Validated an antivirus solution is not installed on $env:COMPUTERNAME."
    }

    if ($null -eq $Status) {
        if ($Running){
            $Status = "not_a_finding"
            $finding_details = "Validated an antivirus solution is being utilized by $env:COMPUTERNAME." +
            "`n`nGet-Service -Name $($AntiVirus.Name)`n$($AntiVirus | Out-string)"

        }
        else {
            $Status = 'open'
            $finding_details = "Validated an antivirus is installed on $env:COMPUTERNAME, but is not Running." +
            "`n`nGet-Service -Name $($AntiVirus.Name)`n$($AntiVirus | Out-string)"
        }
    }

    $Result = [ordered]@{
        Status          = $Status
        Comment         = (Get-FindingComment).$Status
        Finding_Details = $finding_details
    }
    return $Result
}

Function Get-V254249 {
    $ENS = Get-Process -Name mfetp -ErrorAction SilentlyContinue # Trellix Threat Prevent

    if ($ENS.Responding){
        $Status = "not_a_finding"
        $finding_details = "Validated $($ENS.Description) is running on $env:COMPUTERNAME." +
        "$($ENS.Description) prevents threats from accessing systems, scans files automatically when they are" +
        " accessed, and runs targeted scans for malware on client systems"
    }
    else {
        $Status = "open"
        $finding_details = "Validated a HIPS/HIDS solution is not utilized on $env:COMPUTERNAME."
    }

    $Result = [ordered]@{
        Status          = $Status
        Comment         = (Get-FindingComment).$Status
        Finding_Details = $finding_details + "Get-Process -Name mfetp | Select  Company, Description, Product, Responding" +
        "$($ENS | Select-Object  Company, ProcessName, Description, Product, Responding | Out-String)"
    }
    return $Result
}

Function Get-V254251 {
    $Result = [ordered]@{
        Status = 'not_a_finding'
        Comment = (Get-FindingComment).not_a_finding
        Finding_Details = "Validated 'Network access: Let Everyone permissions apply to anonymous users'" +
        " is set to disabled via Server STIG GPO.`n`nicacls C:\`n`n$(icacls c:\ | Out-String)"
    }
    return $Result
}

Function Get-V254252 {
    $Result = [ordered]@{
        Status = 'not_a_finding'
        Comment = (Get-FindingComment).not_a_finding
        Finding_Details = "Validated 'Network access: Let Everyone permissions apply to anonymous users'" +
        " is set to disabled via Server STIG GPO.`n`nicacls 'C:\Program Files'`n`n$(icacls 'C:\Program Files' | Out-String)" +
        "`n`nicacls 'C:\Program Files (x86)'`n`n$(icacls 'C:\Program Files (x86)' | Out-String)"
    }
    return $Result
}

Function Get-V254253 {
    $Result = [ordered]@{
        Status = 'not_a_finding'
        Comment = (Get-FindingComment).not_a_finding
        Finding_Details = "Validated 'Network access: Let Everyone permissions apply to anonymous users'" +
        " is set to disabled via Server STIG GPO.`n`nicacls 'C:\Windows'`n`n$(icacls 'C:\Windows' | Out-String)"
    }
    return $Result
}

Function Get-V254254 {
    $HKLM_SECURITY = Get-Acl HKLM:\SECURITY
    $HKLM_SOFTWARE = Get-Acl HKLM:\SOFTWARE
    $HKLM_SYSTEM = Get-Acl HKLM:\SYSTEM
    $AccessControlType = "Allow"
    
    # Permission sets per STIG Check
    $Security = [ordered]@{
        "NT AUTHORITY\SYSTEM" = [ordered]@{
            RegistryRights = "FullControl"
        }
        "BUILTIN\Administrators" = [ordered]@{
            RegistryRights = "ReadKey, ChangePermissions"
        }
    }

    $Software_System = [ordered]@{
        "CREATOR OWNER" = [ordered]@{
            RegistryRights = "FullControl"
        }
        "NT AUTHORITY\SYSTEM" = [ordered]@{
            RegistryRights = "FullControl"
        }
        "BUILTIN\Administrators" = [ordered]@{
            RegistryRights = "FullControl"
        }
        "BUILTIN\Users" = [ordered]@{
            RegistryRights = "ReadKey"
        }
        "APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES" = [ordered]@{
            RegistryRights = "ReadKey"
        }
        "S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681" = [ordered]@{
            RegistryRights = "ReadKey"
        }
    }

    # Create Tables to compare actual ACL permissions to expected STIG ACL permissions for each Registry Key
    $Index = 0
    while ($Index -lt $HKLM_SECURITY.Access.Count) {
        $HKLM_SECURITY_ACL += [ordered]@{
            $HKLM_SECURITY.Access.IdentityReference.Value[$Index] = [ordered]@{
                RegistryRights    = $HKLM_SECURITY.Access.RegistryRights[$Index]
                AccessControlType = $HKLM_SECURITY.Access.AccessControlType[$Index]
                IdentityReference = $HKLM_SECURITY.Access.IdentityReference[$Index]
                IsInherited       = $HKLM_SECURITY.Access.IsInherited[$Index]
                InheritanceFlags  = $HKLM_SECURITY.Access.InheritanceFlags[$Index]
                PropagationFlags  = $HKLM_SECURITY.Access.PropagationFlags[$Index]
            }
        }
        $Index += 1
    }
    
    $Index = 0
    while ($Index -lt $HKLM_SOFTWARE.Access.Count) {
        $HKLM_SOFTWARE_ACL += [ordered]@{
            $HKLM_SOFTWARE.Access.IdentityReference.Value[$Index] = [ordered]@{
                RegistryRights    = $HKLM_SOFTWARE.Access.RegistryRights[$Index]
                AccessControlType = $HKLM_SOFTWARE.Access.AccessControlType[$Index]
                IdentityReference = $HKLM_SOFTWARE.Access.IdentityReference[$Index]
                IsInherited       = $HKLM_SOFTWARE.Access.IsInherited[$Index]
                InheritanceFlags  = $HKLM_SOFTWARE.Access.InheritanceFlags[$Index]
                PropagationFlags  = $HKLM_SOFTWARE.Access.PropagationFlags[$Index]
            }
        }
        $Index += 1
    }

    $Index = 0
    while ($Index -lt $HKLM_SYSTEM.Access.Count) {
        $HKLM_SYSTEM_ACL += [ordered]@{
            $HKLM_SYSTEM.Access.IdentityReference.Value[$Index] = [ordered]@{
                RegistryRights    = $HKLM_SYSTEM.Access.RegistryRights[$Index]
                AccessControlType = $HKLM_SYSTEM.Access.AccessControlType[$Index]
                IdentityReference = $HKLM_SYSTEM.Access.IdentityReference[$Index]
                IsInherited       = $HKLM_SYSTEM.Access.IsInherited[$Index]
                InheritanceFlags  = $HKLM_SYSTEM.Access.InheritanceFlags[$Index]
                PropagationFlags  = $HKLM_SYSTEM.Access.PropagationFlags[$Index]
            }
        }
        $Index += 1
    }

    # Compare server settings to expected settings
    foreach ($key in $HKLM_SECURITY_ACL.Keys){
        if (
            ($HKLM_SECURITY_ACL.$key.AccessControlType -eq $AccessControlType) -and
            ($HKLM_SECURITY_ACL.$key.RegistryRights -eq $Security.$key.RegistryRights)
        ){
            $SECURITY_ACL += 1    
        }
    }
    foreach ($key in $HKLM_SOFTWARE_ACL.Keys){
        if (
            ($HKLM_SOFTWARE_ACL.$key.AccessControlType -eq $AccessControlType) -and
            ($HKLM_SOFTWARE_ACL.$key.RegistryRights -eq $Software_System.$key.RegistryRights)
        ){
            $SOFTWARE_ACL += 1    
        }
    }
    foreach ($key in $HKLM_SYSTEM_ACL.Keys){
        if (
            ($HKLM_SYSTEM_ACL.$key.AccessControlType -eq $AccessControlType) -and
            ($HKLM_SYSTEM_ACL.$key.RegistryRights -eq $Software_System.$key.RegistryRights)
        ){
            $SYSTEM_ACL += 1    
        }
    }
    if (
        ($HKLM_SECURITY.Access.Count -eq $SECURITY_ACL) -and
        ($HKLM_SOFTWARE.Access.Count -eq $SOFTWARE_ACL) -and
        ($HKLM_SYSTEM.Access.Count -eq $SOFTWARE_ACL)
    ){
        $HKLM_Match = $true
    }
    else {
        $HKLM_Match = $false
    }
    
    if ($HKLM_Match){
        $Status = "not_a_finding"
        $finding_details = "Validated $env:COMPUTERNAME's ACL Permissions for HKLM:\SECURITY, HKLM:\SOFTWARE" +
        " HKLM:\SYSTEM meet the criteria for compliance.`n`nHKLM:\SECURITY`n$($HKLM_SECURITY.Access | Out-String)HKLM:\SOFTWARE`n" +
        "$($HKLM_SOFTWARE.Access | Out-String)HKLM:\SYSTEM`n`n$($HKLM_SYSTEM.Access | Out-String)"
    }
    else {
        $Status = "open"
        $finding_details = "Validated $env:COMPUTERNAME's ACL Permissions for HKLM:\SECURITY, HKLM:\SOFTWARE" +
        " HKLM:\SYSTEM DO NOT meet the criteria for compliance.`n`nHKLM:\SECURITY`n$($HKLM_SECURITY.Access | Out-String)HKLM:\SOFTWARE`n" +
        "$($HKLM_SOFTWARE.Access | Out-String)HKLM:\SYSTEM`n$($HKLM_SYSTEM.Access | Out-String)"
    }

    $Result = [ordered]@{
        Status          = $Status
        Comment         = (Get-FindingComment).$Status
        Finding_Details = $finding_details
    }
    return $Result
}

Function Get-V254255 {
    $Printers = (Get-Printer).Name

    foreach ($Printer in $Printers){
        if (
            ($Printer -notcontains "Microsoft Print to PDF") -or
            ($Printer -notcontains "Microsoft XPS Document Writer")){
                $Status = "open"
                $finding_details = "Validated there are additional printers other than the excluded printers, " +
                "Microsoft Print to PDF and Microsoft XPS Document Writer, for $env:COMPUTERNAME. Printer names provided below.`n`n"
            }
    }

    if ($null -eq $Status){
        $Status = "not_a_finding"
        $finding_details = "Validated only the excluded printers, Microsoft Print to PDF and Microsoft XPS Document Writer, " +
        "are listed for $env:COMPUTERNAME. Printer names provided below`n`n"
    }

    $Result = [ordered]@{
        Status          = $Status
        Comment         = (Get-FindingComment).$Status
        Finding_Details = $finding_details + "(Get-Printer).Name`n`n$($Printers | Format-Table | Out-String)"
    }
    return $Result
}

Function Get-V254256 {
    $Users = Get-LocalUser
    $Admin = ($Users | Where-Object SID -like S-1-5-21*500).SID.Value
    $Guest = ($Users | Where-Object SID -like S-1-5-21*501).SID.Value

    foreach ($User in $Users){
        if (
            ($User.Enabled) -and
            (($User.SID.Value -ne $Admin) -or
            ($User.SID.Value -ne $Guest))
            ){
                $SID = [ordered]@{
                    $User.SID.Value = "Enabled"
                }
            }
    }

    if ($null -eq $SID){
        $Status = "not_a_finding"
        $finding_details = "Validated no local accounts are enabled, excluding BUILTIN\Administrator and BUILTIN\Guest, on $env:COMPUTERNAME.`n`n"
    }
    else {
        foreach ($User_SID in $SID.Keys){
            $LastLogon = ($Users | Where-Object SID -eq $User_SID).LastLogon
            $Today = Get-Date
            if ($Today -gt $LastLogon.AddDays(35)){
                $gt_lastlogon = $true
            }
        }
        if ($gt_lastlogon){
            $Status = "open"
            $finding_details = "Validated additional local accounts are enabled and have not been logged on to " +
            "within the past 35 days on $env:COMPUTERNAME.`n`n"
        }
        else {
            $Status = "not_a_finding"
            $finding_details = "Validated additional local accounts are enable, but have been logged on to" +
            "within the past 35 days on $env:COMPUTERNAME.`n`n"
        }
    }
    
    $Result = [ordered]@{
        Status          = $Status
        Comment         = (Get-FindingComment).$Status
        Finding_Details = $finding_details + "Get-LocalUser | Select Name, Enabled, LastLogon" +
        "`n$(Get-LocalUser | Select-Object Name, Enabled, LastLogon | Out-String)"
    }
    return $Result
}

Function Get-V254257 {
    $Users = Get-LocalUser

    foreach ($User in $Users){
        $User_Table += [ordered]@{
            $User.SID.Value = [ordered]@{
                Enabled = $User.Enabled
                PasswordRequired = $User.PasswordRequired
            }
        }
    }

    foreach ($User in $User_Table.Keys){
        if (
            ($User_Table.$User.Enabled) -and
            ($User_Table.$User.PasswordRequired -eq $false)
            ){
                $Status = "open"
                $finding_details = "Validated there is a local account that is enabled, but does not require" +
                " a password on $env:COMPUTERNAME.`n`n"
        }
    }

    if ($null -eq $Status){
        $Status = "not_a_finding"
        $finding_details = "Validated there are no local accounts that are enabled that do not require a" +
        " password on $env:COMPUTERNAME.`n`n"
    }

    $Result = [ordered]@{
        Status          = $Status
        Comment         = (Get-FindingComment).$Status
        Finding_Details = $finding_details + "Get-Local User$(Get-LocalUser | Select-Object Name, Enabled, PasswordRequired | Out-String)"
    }
    $Result
}

Function Get-V254258 {
    $Users = Get-LocalUser

    foreach ($User in $Users){
        if ($null -eq $User.PasswordExpires){
            $PasswordExpires = "False"
        }
        else {
            $PasswordExpires = "True"
        }
        $User_Table += [ordered]@{
            $User.SID.Value = [ordered]@{
                Enabled = $User.Enabled
                PasswordExpires = $PasswordExpires
            }
        }
    }

    foreach ($User in $User_Table.Keys){
        if (
            ($User_Table.$User.Enabled) -and
            ($User_Table.$User.PasswordExpires -eq "False")
            ){
                $Status = "open"
                $finding_details = "Validated there is a local account that is enabled, but the password" +
                " does not expire on $env:COMPUTERNAME.`n`n"
        }
    }

    if ($null -eq $Status){
        $Status = "not_a_finding"
        $finding_details = "Validated there are no local accounts that are enabled whose passwords do not expire" +
        " on $env:COMPUTERNAME.`n`n"
    }

    $Result = [ordered]@{
        Status          = $Status
        Comment         = (Get-FindingComment).$Status
        Finding_Details = $finding_details + "Get-Local User$(Get-LocalUser | Select-Object Name, Enabled, PasswordExpires | Out-String)"
    }
    $Result
}

Function Get-V254259 {
    $ENS = Get-Process -Name mfetp -ErrorAction SilentlyContinue # Trellix Scanner Service

    if ($ENS.Responding){
        $Status = "not_a_finding"
        $finding_details = "Validated $($ENS.Description) is running on $env:COMPUTERNAME." +
        "$($ENS.Description) prevents threats from accessing systems, scans files automatically when they are" +
        " accessed, and runs targeted scans for malware on client systems"
    }
    else {
        $Status = "open"
        $finding_details = "Validated a system files are not monitored for unauthorized changes on $env:COMPUTERNAME."
    }

    $Result = [ordered]@{
        Status          = $Status
        Comment         = (Get-FindingComment).$Status
        Finding_Details = $finding_details + "`n`nGet-Process -Name mfetp | Select  Company, Description, Product, Responding" +
        "`n$($ENS | Select-Object  Company, ProcessName, Description, Product, Responding | Out-String)"
    }
    return $Result
}

Function Get-V254260 {
    $Shares = Get-SmbShare

    $Allowed_Shares = [ordered]@{
        'ADMIN$' = $true
        'C$' = $true
        'D$' = $true
        'IPC$' = $true
    }

    foreach ($share in $Shares.Name){
        if ($Allowed_Shares.Keys -notcontains $share){
            $Status = 'open'
            $finding_details = "Validated there are NOT only system-created shares such as 'ADMIN$', 'C$', and 'IPC$' that exist on the system."
            
        }
    }
    if ($null -eq $Status){
        $Status = "not_applicable"
        $finding_details = "Validated there are only system-created shares such as 'ADMIN$', 'C$', and 'IPC$' that exist on the system." +
        "'D$' is system-created share for the Data (D:\) Volume."
    }

    $Result = [ordered]@{
        Status          = $Status
        Comment         = (Get-FindingComment).$Status
        Finding_Details = $finding_details + "`n`nGet-SMBShare`n$($Shares | Out-String)"
    }
    return $Result
}

Function Get-V254261 {
    $Drives = Get-Volume | Where-Object DriveLetter -ne $null
    Write-Host "Checking for *.pfx and *.p12 files on $env:COMPUTERNAME. This will take roughtly 5 mins to complete."
    foreach ($drive in $Drives.DriveLetter){
        $Path = $drive + ":\"
        $cert_files = Get-ChildItem -Path $Path -Recurse -Include *.pfx, *.p12 -ErrorAction SilentlyContinue
        
        if ($null -ne $cert_files){
            $Status = 'open'
            $finding_details = "Validated there are certificate installation files on $env:COMPUTERNAME."
            foreach($file in $cert_files){
                $cert_str += "`n`nName: $($file.Name)`nResolvedTarget: $($file.ResolvedTarget)`nExists: $($file.Exists)"
            }
        } 
    }

    if ($null -eq $Status){
        $Status = "not_a_finding"
        $finding_details = "Validated there are no *.pfx or *.p12 files on $env:COMPUTERNAME."
    }

    $Result = [ordered]@{
        Status          = $Status
        Comment         = (Get-FindingComment).$Status
        Finding_Details = $finding_details + " Validations completed using Get-ChildItem -Path (INPUT DRIVE" +
        " PATH, e.g. C:\ or D:\) -Recurse -Include *.pfx, *.p12 -ErrorAction SilentlyContinue.`n$cert_str`n`nWARNING: This" +
        " command will take roughly 3-5 mins to complete a recursive search at the C:\ path." 
    }
    return $Result
}

Function Get-V254262 {
    $Result = [ordered]@{
        Status          = "not_a_finding"
        Comment         = (Get-FindingComment).not_a_finding
        Finding_Details = "Validated AWS Gov Cloud has adequate physical security protections, outlined here 'https://aws.amazon.com/compliance/data-center/controls/'." +
        " In addition to AWS's physical security measure, each of EOSS EC2 Volumes are encrypted to meet data at rest requirements."
    }
    return $Result
}

Function Get-V254263 {
    $Result = [ordered]@{
        Status          = "not_a_finding"
        Comment         = (Get-FindingComment).not_a_finding
        Finding_Details = "Validated the latest version of TLS are utilized for secure connections, and weaker TLS and SSL" +
        " connections are disabled through the registry. Encrypted VPNs are also utilized to connect to AVHE desktops and AWS resources."
    }
    return $Result
}

Function Get-V254264 {
    $WindowsFeatures = Get-WindowsFeature | Where-Object Installed -eq $true | Select-Object DisplayName, Name, InstallState | Format-List
    $WindowsFeatures = $WindowsFeatures | Out-String

    $Result = [ordered]@{
        Status          = "not_a_finding"
        Comment         = (Get-FindingComment).not_a_finding
        Finding_Details = "Validated Windows Roles and Features for $env:COMPUTERNAME are documented in the server's SOP. These are" +
        " required for application functionality and Server Management.`n`n$WindowsFeatures"
    }
    return $Result
}

Function Get-V254265 {
    $Firewall = Get-Service -Name "mfefire" -ErrorAction SilentlyContinue

    if ($null -eq $Firewall){
        $Status = "open"
        $finding_details = "Validated a host-based firewall is not installed on $env:COMPUTERNAME.`n`n"
    }
    elseif ($Firewall.Status -ne "Running"){
        $Status = "open"
        $finding_details = "Validated a host-based firewall is installed, but not running on $env:COMPUTERNAME.`n`n"
    }
    else {
        $Status = "not_a_finding"
        $finding_details = "Validated a host-based firewall is installed and running on $env:COMPUTERNAME.`n`n"
    }

    $Result = [ordered]@{
        Status          = $Status
        Comment         = (Get-FindingComment).$Status
        Finding_Details = $finding_details + "Get-Service -Name mfefire`n`n$($Firewall | Out-String)"
    }
    return $Result
}

Function Get-V254266 {
    $ENS = Get-Process -Name mfetp -ErrorAction SilentlyContinue # Trellix Threat Prevent

    if ($ENS.Responding){
        $Status = "not_a_finding"
        $finding_details = "Validated DoD-approved ESS Software is installed and properly operating on $env:COMPUTERNAME. The ESS" +
        "Software is maintained by DCOPS HBSS Administrators."
    }
    else {
        $Status = "open"
        $finding_details = "Validated DoD-approved ESS Software is NOT installed and properly operating on $env:COMPUTERNAME. Please" +
        "install the proper required software from DCOPS HBSS Administrators."
    }

    $Result = [ordered]@{
        Status          = $Status
        Comment         = (Get-FindingComment).$Status
        Finding_Details = $finding_details + "`n`nGet-Process -Name mfetp -ErrorAction SilentlyContinue" +
        "`n$($ENS | Select-Object  Company, ProcessName, Description, Product, Responding | Out-String)"
    }
    return $Result
}

Function Get-V254267 {
    $Users = Get-LocalUser
    $Admin = ($Users | Where-Object SID -like S-1-5-21*500).SID.Value
    $Default = ($Users | Where-Object SID -like S-1-5-21*503).SID.Value
    $Guest = ($Users | Where-Object SID -like S-1-5-21*501).SID.Value
    $WDAGUtilityAccount = ($Users | Where-Object SID -like S-1-5-21*504).SID.Value
    $UserList = ($Admin, $Default, $Guest, $WDAGUtilityAccount)
    $TempUsers = Get-LocalUser | Where-Object SID -NotIn $UserList

    if ($null -eq $TempUsers){
        $Status = "not_applicable"
        $finding_details = "Validated no temporary accounts exist on $env:COMPUTERNAME.`n`n"
    }
    else {
        $Status = "open"
        $finding_details = "Validated there are temporary accounts that exist on $env:COMPUTERNAME.`n`n"
    }

    $Result = [ordered]@{
        Status          = $Status
        Comment         = (Get-FindingComment).$Status
        Finding_Details = $finding_details + '$Admin = (Get-LocalUser | Where-Object SID -like S-1-5-21*500).SID.Value' + "`n" +
        '$Default = (Get-LocalUser | Where-Object SID -like S-1-5-21*503).SID.Value' + "`n" + 
        '$Guest = (Get-LocalUser | Where-Object SID -like S-1-5-21*501).SID.Value' + "`n" +
        '$WDAGUtilityAccount = ($Users | Where-Object SID -like S-1-5-21*504).SID.Value' + "`n" +
        '$UserList = ($Admin, $Default, $Guest, $WDAGUtilityAccount)' + "`n`nGet-LocalUser | Where-Object SID -NotIn " + '$UserList' +
        " Select Name, AccountExpires, SID`n`n$($TempUsers | Select-Object Name, AccountExpires, SID | Format-List | Out-String)"
    }
    return $Result
}

Function Get-V254268 {
    $Users = Get-LocalUser
    $Admin = ($Users | Where-Object SID -like S-1-5-21*500).SID.Value
    $Default = ($Users | Where-Object SID -like S-1-5-21*503).SID.Value
    $Guest = ($Users | Where-Object SID -like S-1-5-21*501).SID.Value
    $WDAGUtilityAccount = ($Users | Where-Object SID -like S-1-5-21*504).SID.Value
    $UserList = ($Admin, $Default, $Guest, $WDAGUtilityAccount)
    $TempUsers = Get-LocalUser | Where-Object SID -NotIn $UserList

    if ($null -eq $TempUsers){
        $Status = "not_applicable"
        $finding_details = "Validated no emergency accounts exist on $env:COMPUTERNAME.`n`n"
    }
    else {
        $Status = "open"
        $finding_details = "Validated there are emergency accounts that exist on $env:COMPUTERNAME.`n`n"
    }

    $Result = [ordered]@{
        Status          = $Status
        Comment         = (Get-FindingComment).$Status
        Finding_Details = $finding_details + '$Admin = (Get-LocalUser | Where-Object SID -like S-1-5-21*500).SID.Value' + "`n" +
        '$Default = (Get-LocalUser | Where-Object SID -like S-1-5-21*503).SID.Value' + "`n" + 
        '$Guest = (Get-LocalUser | Where-Object SID -like S-1-5-21*501).SID.Value' + "`n" +
        '$WDAGUtilityAccount = ($Users | Where-Object SID -like S-1-5-21*504).SID.Value' + "`n" +
        '$UserList = ($Admin, $Default, $Guest, $WDAGUtilityAccount)' + "`n`nGet-LocalUser | Where-Object SID -NotIn " + '$UserList' +
        " Select Name, AccountExpires, SID`n`n$($TempUsers | Select-Object Name, AccountExpires, SID | Format-List | Out-String)"
    }
    return $Result
}

Function Get-V254279 {
    $FTP = get-windowsFeature | Where-Object Name -like *ftp* | Where-Object Installed -eq $true

    if ($null -eq $FTP){
        $Status = "not_applicable"
        $finding_details = "Validated $env:COMPUTERNAME does not have FTP installed."
    }
    else {
        $Status = "open"
        $finding_details = "Validated $env:COMPUTERNAME has FTP installed. Please validate FTP is set to disabled for Anonymous Authentication."
    }

    $Result = [ordered]@{
        Status          = $Status
        Comment         = (Get-FindingComment).$Status
        Finding_Details = $finding_details + "`n`nGet-WindowsFeature | Where-Object Name -Like '*ftp*'`n`n$($FTP | Select-Object Name, DisplayName, InstallState | Format-List | Out-String)"
    }
    return $Result
}

Function Get-V254280 {
    $FTP = get-windowsFeature | Where-Object Name -like *ftp* | Where-Object Installed -eq $true

    if ($null -eq $FTP){
        $Status = "not_applicable"
        $finding_details = "Validated $env:COMPUTERNAME does not have FTP installed."
    }
    else {
        $Status = "open"
        $finding_details = "Validated $env:COMPUTERNAME has FTP installed. Please validate FTP shared resources."
    }

    $Result = [ordered]@{
        Status          = $Status
        Comment         = (Get-FindingComment).$Status
        Finding_Details = $finding_details + "`n`nGet-WindowsFeature | Where-Object Name -Like '*ftp*'`n`n$($FTP | Select-Object Name, DisplayName, InstallState | Format-List | Out-String)"
    }
    return $Result
}

Function Get-V254281 {
    $Type = (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters).type
    
    if ($Type -eq "NT5DS"){
        $Status = "not_a_finding"
    }
    else {
        $Status = "open"
    }

    $Result = [ordered]@{
        Status = $Status
        Comment = (Get-FindingComment).$Status
        Finding_Details = "Validated $env:COMPUTERNAME uses an NTP Client Type '$Type'.`n`nGet-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" +
        "`n$(Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters | Out-String) "
    }
    return $Result
}

Funciton Get-V254282 {
    [cmdletbinding()]
    param(
        [Parameter(Position=0, Mandatory=$true)]
        $Info
    )

}