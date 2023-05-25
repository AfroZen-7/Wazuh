##[Ps1 To Exe]
##
##Kd3HDZOFADWE8uK1
##Nc3NCtDXThU=
##Kd3HFJGZHWLWoLaVvnQnhQ==
##LM/RF4eFHHGZ7/K1
##K8rLFtDXTiW5
##OsHQCZGeTiiZ4tI=
##OcrLFtDXTiW5
##LM/BD5WYTiiZ4tI=
##McvWDJ+OTiiZ4tI=
##OMvOC56PFnzN8u+Vs1Q=
##M9jHFoeYB2Hc8u+Vs1Q=
##PdrWFpmIG2HcofKIo2QX
##OMfRFJyLFzWE8uK1
##KsfMAp/KUzWJ0g==
##OsfOAYaPHGbQvbyVvnQX
##LNzNAIWJGmPcoKHc7Do3uAuO
##LNzNAIWJGnvYv7eVvnQX
##M9zLA5mED3nfu77Q7TV64AuzAgg=
##NcDWAYKED3nfu77Q7TV64AuzAgg=
##OMvRB4KDHmHQvbyVvnQX
##P8HPFJGEFzWE8tI=
##KNzDAJWHD2fS8u+Vgw==
##P8HSHYKDCX3N8u+Vgw==
##LNzLEpGeC3fMu77Ro2k3hQ==
##L97HB5mLAnfMu77Ro2k3hQ==
##P8HPCZWEGmaZ7/K1
##L8/UAdDXTlaDjoLH7DNl5EauZGEna9bb8a7/ksiA8Pn/viaUSJ0RR0BLlyroDV24FOAXRuUausIUaR8jIc4b8aHFCPesS6ZEl/t6Cw==
##Kc/BRM3KXhU=
##
##
##fd6a9f26a06ea3bc99616d4851b372ba
################################
### Script to execute Sysinternals/PSSuspend - Suspend processes executed not part of the approved SoftwarePolicy.
### Aurora Networks Managed Services
### https://www.auroranetworks.net
### info@auroranetworks.net
################################
##########
# PSSupend will be executed using the Process ID in the sysmon_event1 event that triggered the Software Policy Violation.
# The Process ID will be checked against the process file image (full path) and PSSupend will execute if matched.
# A notification balloon will pop up in the notification area
##########
# Read the Alert that triggered the Active Response in manager and convert to Array
$INPUT_JSON = Read-Host
$INPUT_ARRAY = $INPUT_JSON | ConvertFrom-Json 
$INPUT_ARRAY = $INPUT_ARRAY | ConvertFrom-Json
$ErrorActionPreference = "SilentlyContinue"
#Switch For Rule Group From Alert
$switch_condition = ($INPUT_ARRAY."parameters"."alert"."rule"."groups"[1]).ToString()
#Create Notification shown in User's context.
$notification = '{
$msecs=3000
$Text=""An application was suspended due to the software policies in place""
$Title=""Application Suspended""
Add-Type -AssemblyName System.Windows.Forms 
$global:balloon = New-Object System.Windows.Forms.NotifyIcon
$path = (Get-Process -id $pid).Path
$balloon.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($path) 
$balloon.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Warning 
$balloon.BalloonTipText = "$Text"
$balloon.BalloonTipTitle = "$Title" 
$balloon.Visible = $true 
$balloon.ShowBalloonTip($msecs)
}'
switch -Exact ($switch_condition){
"software_policy"
    {
#Extract Process ID and File Path from Alert
       $process_id_alert = $INPUT_ARRAY."parameters"."alert"."data"."win"."eventdata"."processId"
       $process_file_alert = $INPUT_ARRAY."parameters"."alert"."data"."win"."eventdata"."image"
       $process_file_alert = $process_file_alert -replace "\\\\", "\"
#Get-Process by Process ID and extract process full path
       $running_process_name = (Get-Process -Id $process_id_alert -FileVersionInfo).Filename
#Execute PSSuspend if match with alert
       if ($running_process_name -eq $process_file_alert) {
# Get User's Session ID, used for notification popup
        $user_session_id=(Get-Process -PID $process_id_alert).SessionID
# Execute Notification in user's context.
        C:\'Program Files (x86)'\PsTools\psexec64.exe /nobanner /accepteula -i $user_session_id pwsh.exe -executionpolicy bypass -WindowStyle Hidden -Command "& $notification"
# Suspend Process, sleep and then kill it.
        C:\'Program Files (x86)'\PsTools\pssuspend64.exe /nobanner /accepteula $process_id_alert
        Start-Sleep -s 3
        C:\'Program Files (x86)'\PsTools\pskill64.exe /accepteula $process_id_alert
       }
    break;
    }   
}