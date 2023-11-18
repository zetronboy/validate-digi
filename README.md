# validate-digi
## SUMMARY:
Powershell script to validate the DIGI Connect EZ configuration against expected values.
Does not program the DIGI, just checks your settings against validations.cfg
Will replace Jinja2 style {{variable}} it finds with key=value from ip.cfg
Uses SSH to dump the config and itterates through each validation, testing against DIGI configuration.
For validations it does a -ilike *<validation>* to to match within the config. 
If a validation is prefixed with ! it will validate the string does not exist.

## AUTHOR: Joey Collard

## SYNOPSIS:
pass IP of configured DIGI as arg -ip or answer when prompted
include -pass or be prompted, assume admin user if not passed as -user
If no <IP>.cfg can be found, you will be prompted to enter parameters and a cfg file will be created. 
The default .cfg file creates key/value pairs are specific to my use and the validations.cfg.
After <IP>.cfg exists, you would need to modify it directly or delete to change espected values for the DIGI.
Reads from the DIGI, assumes login username admin if not supplied. You must supply the password for SSH.
runs each of the validations.cfg lines after replacing {{key}} with values from <IP>.cfg, like a Jinja2 template.
You can run the same validations.cfg against all your DIGI because they each have a <IP>.cfg with replacement values to expect.
lines that dont match get a -FAIL. Edit the DIGI using web to correct and run again.

## REQUIRES:
PUTTY is required: Makes use of PLINK.EXE, part of a Putty install. Uses SSH to pull DIGI config. 
You must enable the SSH Service on the DIGI (default setting) on port 22.

## EXAMPLE:
powershell -f validate-digi.ps1 -ip 172.28.1.2 -pass supersecretpass -user admin
