##########################################################################################################
##########################################################################################################

<#
.SYNOPSIS

    Analyses Azure AD users to make recommendations on how to improve their MFA stance.


.DESCRIPTION

    Analyses Azure AD users to make recommendations on how to improve each user's MFA configuration. 

    Can target a group by ObjectId or analyse all users in a tenant.

    Can add user-specific location information: UPN domain, usage location and country.

    Can produce a date and time stamped CSV report of per user recommendations.

    Use -Verbose for insight into the script's activities.

    IMPORTANT:

    * You can not use a guest (B2B) account to run this script against the target tenant. This is a 
      limitation of the MSOnline PowerShell module. The script will execute in the guest's home tenant,
      not the target tenant.

    * Ensure you run the script with an account that can enumurate user properties.


.EXAMPLE

    .\MfaAuthMethodAnalysis.ps1 -TenantId 9959f32b-837b-41db-b6e5-32277e344292

    Creates per user recommendations for all users in the target tenant and displays the results to screen.


.EXAMPLE

    .\MfaAuthMethodAnalysis.ps1 -TenantId 9959f32b-837b-41db-b6e5-32277e344292 -TargetGroup 6424cd24-ee16-472f-bad6-85427c9febc2

    Creates per user recommendations for each user in the target group and displays the results to screen.


.EXAMPLE

    .\MfaAuthMethodAnalysis.ps1 -TenantId 9959f32b-837b-41db-b6e5-32277e344292 -CsvOutput -Verbose

    Creates a date and time stamped CSV file in the scripts execution directory with per user recommendations 
    for all users in the tenant. Has verbose notation to screen.

.EXAMPLE

    .\MfaAuthMethodAnalysis.ps1 -TenantId 9959f32b-837b-41db-b6e5-32277e344292 -LocationInfo -CsvOutput

    Creates a date and time stamped CSV file in the scripts execution directory with per user recommendations 
    for all users in the tenant. Includeds location information: UPN domain, usage location and country.


.NOTES
    THIS CODE-SAMPLE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED 
    OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR 
    FITNESS FOR A PARTICULAR PURPOSE.

    This sample is not supported under any Microsoft standard support program or service. 
    The script is provided AS IS without warranty of any kind. Microsoft further disclaims all
    implied warranties including, without limitation, any implied warranties of merchantability
    or of fitness for a particular purpose. The entire risk arising out of the use or performance
    of the sample and documentation remains with you. In no event shall Microsoft, its authors,
    or anyone else involved in the creation, production, or delivery of the script be liable for 
    any damages whatsoever (including, without limitation, damages for loss of business profits, 
    business interruption, loss of business information, or other pecuniary loss) arising out of 
    the use of or inability to use the sample or documentation, even if Microsoft has been advised 
    of the possibility of such damages, rising out of the use of or inability to use the sample script, 
    even if Microsoft has been advised of the possibility of such damages. 

#>

##########################################################################################################

#Requires -version 3
#Requires -Modules @{ModuleName="MSOnline"; ModuleVersion="1.1.183.57"}

#Version: 1.4

##########################################################################################################

################################
#Define and validate Parameters
################################

[CmdletBinding()]
param(

    #The unique ID of the tenant to target for analysis
    [Parameter(Mandatory,Position=0)]
    [string]$TenantId,

    #The unique ID of the group to analyse
    [Parameter(Position=1)]
    [string]$TargetGroup,

    #Use this switch to include user-specific location information
    [Parameter(Position=2)]
    [switch]$LocationInfo,

    #Use this switch to create a date and time stamped CSV file
    [Parameter(Position=3)]
    [switch]$CsvOutput

    )

##########################################################################################################

##################
#region Functions
##################

#############################################
function Analyse-MsolUserStrongAuthMethods {

    [CmdletBinding()]
    param(

        #A user object to process
        [Parameter(ValueFromPipeline,Position=0)]
        [Microsoft.Online.Administration.User]$User

        )

    #Set user properties
    $UserPrincipalName = $_.UserPrincipalName
    $DisplayName = $_.DisplayName
    [string]$ObjectId = $_.ObjectId

    if ($LocationInfo) {

        $UpnDomain = ($_.UserPrincipalName).Split("@")[1]
        $UsageLocation = $_.UsageLocation
        $Country = $_.Country

    }

    $MfaAuthMethodCount = $_.StrongAuthenticationMethods.Count

    
    #Count number of methods
    if ($MfaAuthMethodCount -eq 0) {

        [array]$Recommendations = "'Register for MFA, preferably with the Microsoft Authenticator mobile app and also with a phone number, used for SMS or Voice.'"

    }
    else {

        #Do some analysis
        switch ($_.StrongAuthenticationMethods) {
            
            #Check default method
            {$_.IsDefault -eq $true} {
         
                $DefaultMethod = $_.MethodType
            
                if ($_.MethodType -ne "PhoneAppNotification") {

                    [array]$Recommendations += "'Consider setting the Microsoft Authenticator mobile app as the default method.'"

                }

            }

            #Check for method type - PhoneAppNotification
            {$_.MethodType -eq "PhoneAppNotification"} {
             
                $AppNotification = "Yes"

                if ($MfaAuthMethodCount -eq 1) {

                    [array]$Recommendations += "'Register at least another authentication method, preferably a verification code from the mobile app or hardware OATH token. A user can have up to five hardware OATH tokens or mobile apps registered. Phone number can also be used for Voice or SMS.'"

                }
            
            
            } 

            #Check for method type - PhoneAppOTP
            {$_.MethodType -eq "PhoneAppOTP"} {
            
                $OathTotp = "Yes"

                if ($MfaAuthMethodCount -eq 1) {

                    [array]$Recommendations += "'Register at least another authentication method, preferably the Microsoft Authenticator mobile app. A user can have up to five hardware OATH tokens or mobile apps registered.'"

                }
            
            } 

            #Check for method type - OneWaySMS
            {$_.MethodType -eq "OneWaySMS"} {
            
                $SMS = "Yes"
            
            }

            #Check for method type - TwoWayVoiceMobile
            {$_.MethodType -eq "TwoWayVoiceMobile"} {

                $Phone = "Yes"        
            
            }

            #Check for method type - OneWaySMS
            {$_.MethodType -eq "TwoWayVoiceAlternateMobile"} {
            
                $AltPhone = "Yes"     
            
            }

        }

    }


    #More recommendations - phone options only
    if ((($SMS) -and ($Phone)) -and ((!$OathTotp) -and (!$AppNotification))) {

        [array]$Recommendations += "'Register at least another authentication method, preferably the Microsoft Authenticator mobile app or hardware OATH token. A user can have up to five hardware OATH tokens or mobile apps registered.'"      

    }


    #More recommendations - Notification and OATH OTP, no phone nubers
    if (((!$SMS) -and (!$Phone) -and (!$AltPhone)) -and (($OathTotp) -and ($AppNotification))) {

        [array]$Recommendations += "'Register a phone number to be used for SMS and Voice.'"       

    }


    #More recommendations - if no Alternative phone number
    if (!$AltPhone) {

        [array]$Recommendations += "'Consider adding an alternative phone number for additional resilience.'"       

    }


    if ($LocationInfo) {

        $AnalysedUser = [pscustomobject]@{

            UserPrincipalName = $UserPrincipalName
            DisplayName = $DisplayName
            ObjectId = $ObjectId
            UpnDomain = $UpnDomain
            UsageLocation = $UsageLocation
            Country = $Country
            MfaAuthMethodCount = $MfaAuthMethodCount
            DefaultMethod = $DefaultMethod
            AppNotification = $AppNotification
            OathTotp = $OathTotp
            Sms = $Sms
            Phone = $Phone
            AltPhone = $AltPhone
            Recommendations = $Recommendations

        }

    }
    else {

        $AnalysedUser = [pscustomobject]@{

            UserPrincipalName = $UserPrincipalName
            DisplayName = $DisplayName
            ObjectId = $ObjectId
            MfaAuthMethodCount = $MfaAuthMethodCount
            DefaultMethod = $DefaultMethod
            AppNotification = $AppNotification
            OathTotp = $OathTotp
            Sms = $Sms
            Phone = $Phone
            AltPhone = $AltPhone
            Recommendations = $Recommendations

        }


    }

    Write-Verbose -Message "$(Get-Date -f T) - User anaylsis completed"

    return $AnalysedUser

}   #end function


#########################################################
#Function to create a CSV friendly object for conversion
function Expand-Recommendations {

    [cmdletbinding()]
    param (
        [parameter(ValueFromPipeline)]
        [psobject]$PsCustomObject
    )
    
    begin {

        #Mark that we don't have properties
        $SchemaObtained = $False

    }

    process {
        
        #If this is the first iteration get object properties
        if (!$SchemaObtained) {

            $OutputOrder = $PsCustomObject.psobject.properties.name
            $SchemaObtained = $true

        }

        #Loop thorugh the supplied object and process individually
        $PsCustomObject | ForEach-Object {

            #Capture each element
            $singleGraphObject = $_

            #New parent object for edited / expanded values
            $ExpandedObject = New-Object -TypeName PSObject

            #Loop through the properties
            $OutputOrder | ForEach-Object {

                #Recommendations property has to have commas added
                if ($_ -eq "Recommendations") {
                    
                    #Ensure we have a non-empty value if there's nothing in Recommendations
                    $CSVLine = " "

                    #Get variables from authMethods property
                    $Properties = $singleGraphObject.$($_)

                    #Loop through each property and add to a single string with a seperating comma (for CSV)
                    $Properties | ForEach-Object {

                        $CSVLine += "$_,"

                    }

                    #Add edited list of values for authmethods property to parent object
                    Add-Member -InputObject $ExpandedObject -MemberType NoteProperty -Name $_ -Value $CSVLine.TrimEnd(0,",").TrimStart()

                }
                else {

                    #Add single value property to parent object
                    Add-Member -InputObject $ExpandedObject -MemberType NoteProperty -Name $_ -Value $(($singleGraphObject.$($_) | Out-String).Trim())

                }

            }

            #Return completed parent object
            $ExpandedObject

        }

    }

}   #end function

#endregion functions


#############
#region Main
#############

#Tracking variables
$UsersProcessed = 0
$ScriptStartTime = Get-Date

#Verbose output
Write-Verbose -Message "$(Get-Date -f T) - Script started..."
if ($LocationInfo) {Write-Verbose -Message "$(Get-Date -f T) - User location information included"}
if ($CsvOutput) {Write-Verbose -Message "$(Get-Date -f T) - CSV output selected"}


#Some additional paramter validation outside of param()

#Try and connect to Azure AD
try {$DomainInfo = Get-MsolDomain -TenantId $TenantId -ErrorAction SilentlyContinue}
catch {}

if ($DomainInfo) {

    Write-Verbose -Message "$(Get-Date -f T) - Connection to $TenantId established"

}
else {

    #Error handling
    switch -Wildcard ($error[0].exception) {
            
        "*You must call the Connect-MsolService cmdlet before calling any other cmdlets*" {

            #Present connection pop-up
            Write-Verbose -Message "$(Get-Date -f T) - Calling Connect-MsolService cmdlet"
            Connect-MsolService -ErrorAction SilentlyContinue
            
            #Populate the DomainInfo variable if Connect-MsolService works
            if ($?) {
                
                Write-Verbose -Message "$(Get-Date -f T) - Connection to $TenantId established"
                $DomainInfo = $true
            }
            else {

                Write-Verbose "$(Get-Date -f T) - Connection to $TenantId could not be established"

            }

        }

        "*The TenantID you have provided is invalid. Check the TenantID and try again*" {

            Write-Verbose -Message "$(Get-Date -f T) - $($error[0])"
            Write-Warning -Message "$(Get-Date -f T) - The Tenant ID provided is invalid - $TenantId"

        }

        "*Guid should contain 32 digits with 4 dashes*" {

            Write-Verbose -Message "$(Get-Date -f T) - $($error[0])"
            Write-Warning -Message "$(Get-Date -f T) - Please provide a valid GUID for the Tenant ID"

        }

        "*Access Denied. You do not have permissions to call this cmdlet*" {

            Write-Verbose -Message "$(Get-Date -f T) - $($error[0])"
            Write-Warning -Message "$(Get-Date -f T) - Access Denied - it's likley that you are trying to connect to a tenant you have not authenticated to"

        }

        default {

            Write-Warning -Message "$(Get-Date -f T) - $($error[0])"

        }

    }

}

#Check if we have a connection
if ($DomainInfo) {

    #Check if we need to create a CSV file
    if ($CsvOutput) {

        #Output file
        $Now = "{0:yyyyMMdd_hhmmss}" -f (Get-Date)
        $OutputFile = "MfaAuthMethodAnalysis_$now.csv"

        Write-Verbose -Message "$(Get-Date -f T) - Creating CSV file - $OutputFile"

        #Create file with header
        if ($LocationInfo) {

            Add-Content -Value "UserPrincipalName,DisplayName,ObjectId,UpnDomain,UsageLocation,Country,MfaAuthMethodCount,DefaultMethod,AppNotification,OathTotp,Sms,Phone,AltPhone,Recommendations" `
                        -Path $OutputFile

        }
        else {

            Add-Content -Value "UserPrincipalName,DisplayName,ObjectId,MfaAuthMethodCount,DefaultMethod,AppNotification,OathTotp,Sms,Phone,AltPhone,Recommendations" `
                        -Path $OutputFile

        }

        if ($?) {

            Write-Verbose -Message "$(Get-Date -f T) - Header written to CSV file - $OutputFile"
            
        }
        else {

            Write-Warning -Message "$(Get-Date -f T) - Failed to write header to CSV file - $OutputFile"
            Write-Warning -Message "$(Get-Date -f T) - Reverting to non-CSV output mode"
            
            #Prevent further CSV processing
            $CsvOutput = $false

        }

    }

    #We have a connction so start doing stuff... let's check if we are targetting a group
    if ($TargetGroup) {
    
        Write-Verbose -Message "$(Get-Date -f T) - Checking for target group - $TargetGroup"

        #Ensure the group is valid 
        try {$GroupInfo = Get-MsolGroup -ObjectId $TargetGroup -ErrorAction SilentlyContinue}
        catch {}

        if ($GroupInfo) {

            Write-Verbose -Message "$(Get-Date -f T) - Group $TargetGroup confirmed as valid"
            Write-Verbose -Message "$(Get-Date -f T) - Group Display Name = $(($GroupInfo).Displayname); Group Type = $(($GroupInfo).GroupType)"
            Write-Verbose -Message "$(Get-Date -f T) - Enumerating users for $TargetGroup..."

            #We have he target group so let's enumerate the users
            try {$TargetUsers = Get-MsolGroupMember -GroupObjectId $TargetGroup -All}
            catch {}

            if ($TargetUsers) {

                Write-Verbose -Message "$(Get-Date -f T) - $(($TargetUsers).Count) users found"

                #Now we have users let's get an msol user object
                $TargetUsers | ForEach-Object {

                    Get-MsolUser -ObjectId $_.objectID -ErrorAction SilentlyContinue | ForEach-Object {

                        Write-Verbose -Message "$(Get-Date -f T) - Processing $(($_).UserPrincipalName)"
                    
                        #Call the analysis function
                        $TargetUser = Analyse-MsolUserStrongAuthMethods -User $_

                        #Determine if we write to screen or file
                        if ($CsvOutput) {
                            
                            Write-Verbose -Message "$(Get-Date -f T) - Converting analysis to CSV format"

                            #Call property expansion function and pipe into a CSV format
                            $CsvFormat = $TargetUser | Expand-Recommendations | ConvertTo-Csv -NoTypeInformation


                            Write-Verbose -Message "$(Get-Date -f T) - Writing conversion to CSV file"

                            #Write the pertinent CSV line
                            Add-Content -Value $CsvFormat[1] -Path $OutputFile

                            if ($?) {

                                Write-Verbose -Message "$(Get-Date -f T) - Details successfully written to CSV file"

                            }
                            else {

                                Write-Warning -Message "$(Get-Date -f T) - Failed to write details to CSV file"

                            }

                        }
                        else {

                            #Show user analysis in host
                            $TargetUser

                        }

                        #Increment user count
                        $UsersProcessed++

                    }

                }

            }
            else {

                Write-Verbose -Message "$(Get-Date -f T) - $($error[0])"
                Write-Warning -Message "$(Get-Date -f T) - Issue obtaining members for target group $TargetGroup"
                Write-Warning -Message "$(Get-Date -f T) - Exiting script..."

            }

        }
        else {

            Write-Verbose -Message "$(Get-Date -f T) - $($error[0])"
            Write-Warning -Message "$(Get-Date -f T) - Issue obtaining the target group $TargetGroup"
            Write-Warning -Message "$(Get-Date -f T) - Exiting script..."

        }

    }
    else {
    
        Write-Verbose -Message "$(Get-Date -f T) - Targetting all users in $TenantId"

        #We're not tagtetting a group, so let's process all users
        Get-MsolUser -All -ErrorAction SilentlyContinue | ForEach-Object {
        
            Write-Verbose -Message "$(Get-Date -f T) - Processing $(($_).UserPrincipalName)"

            #Call the analysis function
            $TargetUser = Analyse-MsolUserStrongAuthMethods

            #Determine if we write to screen or file
            if ($CsvOutput) {
                            
                Write-Verbose -Message "$(Get-Date -f T) - Converting analysis to CSV format"

                #Call property expansion function and pipe into a CSV format
                $CsvFormat = $TargetUser | Expand-Recommendations | ConvertTo-Csv -NoTypeInformation


                Write-Verbose -Message "$(Get-Date -f T) - Writing conversion to CSV file"

                #Write the pertinent CSV line
                Add-Content -Value $CsvFormat[1] -Path $OutputFile

                if ($?) {

                    Write-Verbose -Message "$(Get-Date -f T) - Details successfully written to CSV file"

                }
                else {

                    Write-Warning -Message "$(Get-Date -f T) - Failed to write details to CSV file"

                }

            }
            else {

                #Show user analysis in host
                $TargetUser

            }

            #Increment user count
            $UsersProcessed++

        }

    } 
    
}
else {

    #We can't connect... say goodbye
    Write-Warning -Message "$(Get-Date -f T) - Exiting script..."

} 

#Tracking stuff
$ScriptEndTime = Get-Date
$TimeSpan = $ScriptEndTime - $ScriptStartTime
$ProcessingTime = "{0:c}" -f $TimeSpan

Write-Verbose -Message "$(Get-Date -f T) - Total users processed: $UsersProcessed"
Write-Verbose -Message "$(Get-Date -f T) - Total processing time: $ProcessingTime"
Write-Verbose -Message "$(Get-Date -f T) - Script finished!"



#endregion main

##########################################################################################################
##########################################################################################################