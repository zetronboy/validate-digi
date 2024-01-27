# validate-digi
## SUMMARY:
Powershell script to validate the [DIGI Connect EZ](https://www.digi.com/search?q=connect%20ez) configuration against expected values.
Does not program the DIGI, just checks your settings against validations.cfg

## REQUIREMENTS:
Uses plink.exe, part of Putty install (32 or 64bit ok).
Uses Powershell, part of Windows.

## AUTHOR: Joey Collard (NGA)

## SYNOPSIS:
pass IP of configured DIGI as arg -ip or answer when prompted
include -pass or be prompted, assumes admin user if not passed as -user
If no <IP>.cfg can be found, you will be prompted to enter parameters and a .cfg file will be created and used going forward. Edit directly to make changes or delete to reprompt.
The key/value replacements ip.cfg file are specific to my use and the validations.cfg. The program could be extended to validate other devices.
Reads from the DIGI using SSH, and runs each of the validations against the returned config. A temp file commands.bat is run to use plink (part of Putty) to extract the configuration.
Each of the validations.cfg lines are tested against the device config, after replacing {{key}} with values from <IP>.cfg, like a Jinja2 template.

## REQUIRES:
PUTTY is required: Makes use of PLINK.EXE, part of a Putty install. Uses SSH to pull DIGI config. 
You must enable the SSH Service on the DIGI (default setting) on port 22.

## VALIDATIONS:
Will replace Jinja2 style {{variable}} it finds with key=value from <ip>.cfg
Uses SSH (plink, part of Putty install) to dump the config and itterates through each validation, testing against DIGI configuration.
For validations it does a -ilike *<validation>* to to match within the config. 
If a validation is prefixed with ! it will validate the string does not exist.

You can run the same validations.cfg against all your DIGI because they each have a <IP>.cfg with replacement values applied to the validations before testing.
lines that dont match get a -FAIL outp8ut. Edit the DIGI using the browser to correct and run again.

Supports a -config arg that will use a local text file containing DIGI config rather than SSH. Used for development.

## EXAMPLE:
powershell -f validate-digi.ps1 -ip 172.28.1.2 -pass supersecretpass -user admin
