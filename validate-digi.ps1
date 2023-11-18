<#
SUMMARY:
Powershell script to validate the DIGI Connect EZ configuration against expected values.
Does not program the DIGI, just checks your settings against validations.cfg
Uses SSH to dump the config and itterates through each cfg key=value to replace jinja style {{variable}} it finds
For validations it does a -ilike *validate* to to match within the config. 
If a validation is prefixed with ! it will validate the string does not exist.

AUTHOR: Joey Collard (NGA)

SYNOPSIS:
pass IP of configured DIGI as arg -ip or answer when prompted
If no <IP>.cfg can be found, you will be prompted to enter parameters and a cfg file will be created. 
After it exists, you would need to modify it directly or delete to change espected values for the DIGI.
Reads from the DIGI, assumes login/pass admin/Pa55word!
runs each of the validations.cfg lines after replacing {{key}} with values from <IP>.cfg, like a Jinja2 template.
lines that dont match get a -FAIL. Edit the DIGI using web to correct and run again.
Makes use of PLINK.EXE, part of a Putty install.

EXAMPLE:
powershell -f validate-digi.ps1 -ip 172.28.1.2

#>
PARAM(
    [Parameter(Mandatory=$true,HelpMessage="IP Address of configured DIGI to validate")][string]$ip,
    [Parameter(Mandatory=$false,HelpMessage="Saved DIGI config as file")][string]$config,
    [Parameter(Mandatory=$false,HelpMessage="Username for SSH connection")][string]$user,
    [Parameter(Mandatory=$true,HelpMessage="Password for SSH connection")][string]$pass
)

$newline = "`r`n" #powershell escape char is backtick
Write-Host "INSTRUCTIONS:  Configure the DIGI before running this validation."
Write-Host "NB: Only supports DIGI Connect EZ. DIGI must have SSH service enabled." #only tested against MINI single port device
if ($user -eq "")
{
    $user = "admin"
}

$cfgfile_settings = @() # content of key=value replacements as list
$config_path = $config # used for development without DIGI
$cfgfile_path = ".\$ip.cfg"
if ( [System.IO.File]::Exists( $cfgfile_path ) )
{
    $cfgfile_settings = @(Get-Content $cfgfile_path) #force content to list of lines
}
$count = $cfgfile_settings.Length
if ($count -gt 0)
{
    Write-Host "Read $count properties from $cfgfile_path"
} else {
    #prmopt for settings - interactive
    $cfgfile_settings_dict = [ordered]@{ 
        "NAME"="DIGI NAME";
        "CONTACT"="PSAP CONTACT";
        "LOCATION"="PSAP LOCATION";
        "LPG"="LPG IP";
        "IP"="DIGI IP/PFX";        
        "GATEWAY"="DIGI GW IP";
        "DNS1"="DNS1";
        "DNS2"="DNS2";
        "NTP1"="NTP1";
        "NTP2"="NTP2"
    }
    $keys = $cfgfile_settings_dict.Keys
    foreach ($key in $keys)
    {
        $prompt = $cfgfile_settings_dict[$key]
        $value = Read-Host $prompt
        $cfgfile_settings += "$key=$value"
    }    
    $cfgfile_settings | Out-File -FilePath $cfgfile_path # each item in list is appended with newline automatically
}

#find plink location, used to retrieve config via SSH
$plink_path = "C:\Program Files\Putty\plink.exe" 
if ( [System.IO.File]::Exists( $plink_path) -eq $false )
{
    $plink_path = "C:\Program Files (x86)\Putty\plink.exe"
    if ( [System.IO.File]::Exists( $plink_path) -eq $false )
    {
        Write-Host "Could not determine putty install for plink.exe"
        $plink_path = "plink.exe" #maybe it will be in the path or local dir
    }
}

Write-Host "Using Settings:"
$cfgfile_settings -Join $newline | Write-Host

if ($config_path) #cmdline arg -config can override and read from disk instead of SSH for development.
{
    if ( [System.IO.File]::Exists( $config_path ) )
    {
        $config_content = @(Get-Content $config_path)
    } else {
        Write-Error "Missing $config_path"     
    }
} else 
{    
    Write-Host "Retrieving DIGI Config from $ip, you can ignore FATAL below as the CERT is cached."
@"
@echo off
echo caching SSH cert before running script
echo y | "$plink_path" $username@$ip "exit"
(
    timeout /t 2 > nul
    echo a
    timeout /t 1 > nul
    echo show config
    timeout /t 3 > nul
    echo show version
    timeout /t 1 > nul
    echo exit
    timeout /t 1 > nul
    echo q
) | "$plink_path" admin@$ip -pw "$password" -batch
"@ | out-file -FilePath .\ssh-command.bat -Encoding ascii

    #run the Batch command we created above to plink
    $config_content = .\ssh-command.bat
    Remove-Item .\ssh-command.bat #cleanup, that file contained a password.
}

#validations use simple string matching test, case insensative, anywhere in config, partial match ok.
#use ! at begining of a validation to make it negative and will make sure text does not appear.
$validation_path = "validations.cfg"
if ( [System.IO.File]::Exists($validation_path) -eq $false )
{
    Write-Error "Expected a file $validation_path with one or more validations/tests. Will create example file. Review and re-run this script."
    @"
    Firmware Version         : 23.6.1.105
    add network interface eth ipv4 dns end "{{DNS1}}"
    add network interface eth ipv4 dns end "{{DNS2}}"
    auth user admin lockout tries "10"
    cloud drm watchdog "false"
    cloud enable "false"
    network interface eth ipv4 address "{{IP}}"
    network interface eth ipv4 gateway "{{GATEWAY}}"
    network interface eth ipv4 type "static"
    network interface eth ipv6 enable "false"
    schema version "1042"
    !serial port1 idle_timeout
    serial port1 autoconnect conn_type "tcp"
    serial port1 autoconnect destination "{{LPG}}"
    serial port1 autoconnect enable "true"
    serial port1 autoconnect keepalive "true"
    serial port1 autoconnect port "52219"
    serial port1 label "{{NAME}}"
    serial port1 service ssh enable "true"
    serial port1 service ssh port "2501"
    service snmp enable "true"
    service snmp enable2c "true"
    service snmp password "$ob1$7890f3e9$OUsgIWRdYVQS8v1n1TG61VBQTU48ChlBIGzs2h5Osqhi"
    service snmp username "E911"
    system contact "{{CONTACT}}"
    system description "{{NAME}}"
    system location "{{LOCATION}}"
    system name "{{NAME}}"
    system time source 0 server 0 "{{NTP1}}"
    add system time source 0 server end "{{NTP2}}"
"@ | Out-File $validation_path
    exit 1    
}

$tests = @(Get-Content $validation_path) # .\validations.cfg
Write-Output "Validating against $validation_path..." 

function run_validations
{
    <#
    replaces Jinja style {{variables}} in settings before
    looking for each validations in content.
    simple matching -ilike *value*
    use leading ! in validation to verify the string does not exist
    does not match multi-line strings. Does not use Regex.
    made this part a function because it could have some reuse in other projects.
    #>
    PARAM(
        [Parameter(Mandatory=$true,HelpMessage="list of validations")]$validations,
        [Parameter(Mandatory=$true,HelpMessage="list of key=value pairs for substitution")]$settings,
        [Parameter(Mandatory=$true,HelpMessage="text content to validate")]$content
    )
    
    $pass = $fail = $total = 0
    foreach ($test in $validations)
    {
        $test = $test.Trim()
        #Applying cfg substitutions to validation...
        foreach ($setting in $settings)
        {
            $param_name, $param_value = $setting -split "="
            $param_name = $param_name.Trim()
            $param_value = $param_value.Trim()
            $test = $test -replace "{{$param_name}}",$param_value
        }

        $should_not_include = $test.StartsWith("!") # prefix your validation with ! to verify it does not exist in config
        if ($should_not_include)
        {
            $test_without_flags = $test.Substring(1) #remove ! prefix/flag for negation
        } else {
            $test_without_flags = $test
        }

        #IDEA: maybe add more flags later like regex if you find a leading /

        #using case-insensative ilike that does simple match. Using wildcard *test* for max success.
        $matched_teststring = $config_content -ilike "*$test_without_flags*" # will hold matched string if found
        $found_teststring =  [bool]($matched_teststring -ne "")

        if (($found_teststring -eq $true -and $should_not_include -eq $false) -or
            ($found_teststring -eq $false -and $should_not_include -eq $true) )
        {
            $pass += 1 
            Write-Host ("$test - PASS") -ForegroundColor green
        } else {
            $fail +=1 
            if ($should_not_include)
            {
                Write-Host ("$test - FAIL/PRESENT") -ForegroundColor red    
            } else {
                Write-Host ("$test - FAIL/MISSING") -ForegroundColor red    
            }                
        }
        $total +=1
    }
    Write-Host ("Summary:")
    Write-Host ("$total validations total")
    Write-Host ("$pass passed") -ForegroundColor green
    if ($fail -gt 0)
    {
        Write-host ("$fail failed") -ForegroundColor red    
        Write-Host "Validations tested against the following configuration."
        $content | Write-Host
    }
    return @{ "total"=$total; "pass"=$pass; "fail"=$fail } #dict/hash of results
}


run_validations -validations $tests -settings $cfgfile_settings -content $config_content |Out-Null # returns dict

