# Unifi-NVR-Nagios-Icinga2-Check-Script

A small script that can be used to check the Unifi UDM-Pro's for many different services. Use at your own risk. The script is provided with no warranty or support. It was just a quick project that I figured I would share.

It works like any other icinga or nagios script. Very lightly tested, feel free to submit issues if you find anything.


# Usage

usage: check_unifi_udm-pro.py [-h] [-X VALUE] [-u USERNAME] [-p PASSWORD] [--insecure]
                          [-c CERTIFICATE] [-H HOST] [-P PORT] -t
                          {check_adopted_devices, check_upgrade_status, check_support_status, check_failover_status, check_devices_overheating_status, check_device_temperatures, check_devices_cpu_status, check_devices_mem_status}

-h - Get Help
-X - This parameter is used to enter the serial number of your primary gateway when using the check_failover_status function.
-u - Username
-p - Password
-c - Add the path to a certificate for verification.
-H - The script relies on the web API for the UDM-PRO. Enter the hostname or IP of the UDM-PRO here.
-P - Enter the port of the webserver. This is almost always 443.
-t - Specify the check you want to use. Options: {check_adopted_devices, check_upgrade_status, check_support_status, check_failover_status, check_devices_overheating_status, check_device_temperatures, check_devices_cpu_status, check_devices_mem_status}
--insecure - Will disable certificate verification when the scripts submits POST or GET requests on an https url.

Example:

'/usr/lib/nagios/plugins/check_unifi_udm-pro.py' '--insecure' '-H' 'gw.example.com' '-P' '443' '-p' 'P@ssw0rd!' '-t' 'check_devices_mem_status' '-u' 'monitor_user'


Username and password can be a separate "monitoring" account added as a local user on the UDM-PRO.

# Available Checks:
check_adopted_devices: Gets a status code from each adopted device on the network. I'm unsure how Ubiquiti implements this check, but if the "status" is anything but a 1, it will alert.
check_upgrade_status: Checks whether any of the adopted devices need updates.
check_support_status: Checks whether any of the adopted devices have gone EOL (End Of Life).
check_failover_status: Checks whether a setup using "Shadow Mode" (HA) has failed over to secondary.
check_devices_overheating_status: Checks whether the "overheating" attribute is true on any adopted device. I am unsure about how this value is implemented on the Ubiquiti side, so it's untested.
check_device_temperatures: Get the temperature of all adopted devices. The threshold is hardcoded here. Feel free to edit the script and submit a pull request to make it more modular. Default is set to > 50 as alert (critical).
check_devices_cpu_status: Get the CPU usage of all adopted devices. The threshold is hardcoded here too. Default is set to > 70 as alert (critical).
check_devices_mem_status: Get the Memory usage of all adopted devices. The threshold is hardcoded here also. Default is set to > 90 as alert (critical).

                          
