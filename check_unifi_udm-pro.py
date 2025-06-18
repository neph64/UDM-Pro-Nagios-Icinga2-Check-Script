#!/usr/bin/env python3
import argparse
import requests
import json
import urllib3


parser = argparse.ArgumentParser(description="Checks health on UDM-PRO Devices.")


parser.add_argument(
    "-u", "--username",
    dest="username",
    help="Username"
)

parser.add_argument(
    "-p", "--password",
    dest="password",
    help="User Password"
)
parser.add_argument(
    "--insecure",
    dest="insecure",
    action="store_true",
    help="Disable SSL Certificate verification"
)

parser.add_argument(
    "-c", "--certificate",
    dest="certificate",
    help="Specify certificate used to verify requests using SSL",
    required=False
)

parser.add_argument(
    "-H", "--host",
    dest="host",
    help="Specify certificate used to verify requests using SSL",
    required=False
)

parser.add_argument(
    "-P", "--port",
    dest="port",
    help="Specify the port the queries will use",
    required=False
)

parser.add_argument(
    "-t", "--test",
    dest="test",
    help="Which subprogram to run",
    choices=[
        'check_adopted_devices', 'check_upgrade_status', 'check_support_status', 'check_failover_status', 'check_devices_overheating_status', 'check_device_temperatures', 'check_devices_cpu_status', 'check_devices_mem_status'
        ],
    nargs='+',
    required=True
)

parser.add_argument(
    "-X", "--value",
    dest="value",
    help="Some checks require extra info. Use this when passing that info.",
    required=False
)

args = parser.parse_args()
if args.insecure:
    import urllib3
    urllib3.disable_warnings()
    requests.packages.urllib3.disable_warnings() # pylint: disable=no-member
    VERIFY_SSL = False
elif args.certificate != "":
    VERIFY_SSL = args.certificate
else:
    VERIFY_SSL = True


## Setup Authentication, get a token.

gateway = {"ip":args.host,"port":args.port}
headers = {"Accept": "application/json","Content-Type": "application/json"}
loginUrl = 'api/auth/login'
authUrl = f"https://{gateway['ip']}:{gateway['port']}/{loginUrl}"
auth = {"username": args.username,"password": args.password}


session = requests.Session()
authResponse = session.post(authUrl,headers=headers,data=json.dumps(auth), verify=VERIFY_SSL)








def handle_html_err(r: requests.Response) -> str|None:
    """
    Handles API request errors.

    Args:
        r (requests.Response): A response from API call

    Returns:
        str|None: str of error output or None if ok.
    """
    if r.ok:
        return None
    try:
        j = json.loads(r.text)
        errmsg = j['message'] if 'message' in j else r.text
    except Exception as e:
        errmsg = r.text
    return f"API call returned non-200 status code {r.status_code} with output: {errmsg}"




def check_adopted_devices():
    """
    Checks status of adopted devices.

    Returns:
        A check result.
    """
    
    
    result = session.get(
        f"https://{gateway['ip']}:{gateway['port']}"+"/proxy/network/api/s/default/stat/device-basic",
        timeout=15,
        verify=VERIFY_SSL,
        headers=headers,
    )
    if handle_html_err(result) is not None:
        print(str(handle_html_err(result)))
        exit(3)
    data = json.loads(result.content)
    check_status = 0
    for device in data['data']:
        if device['state'] != 1:
            print(f"Issue detected with {device['name']}")
            check_status = 2
        else:
            print(f"{device['name']} is OK")
    exit(check_status)




def check_upgrade_status():
    """
    Checks firmware update status of the devices on the network.

    Returns:
        A check result.
    """
    
    
    result = session.get(
        f"https://{gateway['ip']}:{gateway['port']}"+"/proxy/network/api/s/default/stat/widget/warnings",
        timeout=15,
        verify=VERIFY_SSL,
        headers=headers,
    )
    if handle_html_err(result) is not None:
        print(str(handle_html_err(result)))
        exit(3)
    data = json.loads(result.content)
    check_status = 0
    for device in data['data']:
        if str(device['has_upgradable_devices']).lower() != "false":
            print("Upgrades are available.")
            check_status = 1
        else:
            print("No updates needed")
    exit(check_status)
            


def check_support_status():
    """
    Checks support status of the devices on the network.

    Returns:
        A check result.
    """
    
    
    result = session.get(
        f"https://{gateway['ip']}:{gateway['port']}"+"/proxy/network/api/s/default/stat/widget/warnings",
        timeout=15,
        verify=VERIFY_SSL,
        headers=headers,
    )
    if handle_html_err(result) is not None:
        print(str(handle_html_err(result)))
        exit(3)
    data = json.loads(result.content)
    check_status = 0


    for device in data['data']:
            if device['eol_device_count'] != 0:
                print("There is an EOL device on the network.")
                check_status = 2
            else:
                print("All devices on the network are supported.")

    exit(check_status)





def check_failover_status():
    """
    Checks the status of failover on redundant gateways (Shadow Mode). This check utilizes a serial parameter which gets passed. Enter the serial number of the primary.

    Returns:
        A check result.
    """
    
    
    result = session.get(
        f"https://{gateway['ip']}:{gateway['port']}"+"/proxy/network/api/s/default/stat/device",
        timeout=15,
        verify=VERIFY_SSL,
        headers=headers,
    )
    if handle_html_err(result) is not None:
        print(str(handle_html_err(result)))
        exit(3)
    data = json.loads(result.content)
    primary_serial = args.value

    check_status = 0
    for device in data['data']:
        if str(device['type']).lower() == "udm":
            if str(device['serial']).lower() != primary_serial.lower():
                print("Serial Mismatch - Network has failed over to secondary gateway.")
                check_status = 2
            else:
                print("Primary gateway is active.")
    exit(check_status)


def check_devices_overheating_status():
    """
    Checks the overheat status of all network devices that support it.

    I'm unsure how Ubiquiti implements this api call, or whether it works properly.

    Returns:
        A check result.
    """
    
    
    result = session.get(
        f"https://{gateway['ip']}:{gateway['port']}"+"/proxy/network/api/s/default/stat/device",
        timeout=15,
        verify=VERIFY_SSL,
        headers=headers,
    )
    if handle_html_err(result) is not None:
        print(str(handle_html_err(result)))
        exit(3)
    data = json.loads(result.content)
    check_status = 0
    for device in data['data']:
        if 'overheating' in device:
            if str(device['overheating']).lower() != 'false':
                print(f"{device['name']} IS overheating.")
                check_status = 2
            else:
                print(f"{device['name']} is NOT overheating.")
                
        else:
            print(f"{device['name']} does not support this check.")
    exit(check_status)



def check_device_temperatures():
    """
    Checks the temperature probes on the devices that support it.

    Returns:
        A check result.
    """
    
    
    result = session.get(
        f"https://{gateway['ip']}:{gateway['port']}"+"/proxy/network/api/s/default/stat/device",
        timeout=15,
        verify=VERIFY_SSL,
        headers=headers,
    )
    if handle_html_err(result) is not None:
        print(str(handle_html_err(result)))
        exit(3)
    data = json.loads(result.content)
    check_status = 0
    for device in data['data']:
        if 'temperatures' in device:
            print(f"{device['name']} - Temperatures:")
            for temperature in device['temperatures']:

                if temperature['value'] > 50:
                    print(f"{temperature['name']} - Temperature is {temperature['value']} - Outside of threshold (50)")
                    check_status = 2
                else:
                    print(f"{temperature['name']} - Temperature is {temperature['value']} - Within threshold (50)")
    exit(check_status)

def check_devices_cpu_status():
    """
    Checks the CPU usage for each device.

    Returns:
        A check result.
    """
    
    
    result = session.get(
        f"https://{gateway['ip']}:{gateway['port']}"+"/proxy/network/api/s/default/stat/device",
        timeout=15,
        verify=VERIFY_SSL,
        headers=headers,
    )
    if handle_html_err(result) is not None:
        print(str(handle_html_err(result)))
        exit(3)
    data = json.loads(result.content)
    check_status = 0
    for device in data['data']:
        if 'system-stats' in device:
            if 'cpu' in device['system-stats']:
                if float(device['system-stats']['cpu']) > 70:
                    print(f"{device['name']} CPU usage is high - {device['system-stats']['cpu']}%")
                    check_status = 2
                else:
                    print(f"{device['name']} CPU usage is OK - {device['system-stats']['cpu']}%")
                
    exit(check_status)

def check_devices_mem_status():
    """
    Checks the memory usage for each device.

    Returns:
        A check result.
    """
    
    
    result = session.get(
        f"https://{gateway['ip']}:{gateway['port']}"+"/proxy/network/api/s/default/stat/device",
        timeout=15,
        verify=VERIFY_SSL,
        headers=headers,
    )
    if handle_html_err(result) is not None:
        print(str(handle_html_err(result)))
        exit(3)
    data = json.loads(result.content)
    check_status = 0
    for device in data['data']:
        if 'system-stats' in device:
            if 'cpu' in device['system-stats']:
                if float(device['system-stats']['mem']) > 90:
                    print(f"{device['name']} Memory usage is high - {device['system-stats']['mem']}%")
                    check_status = 2
                else:
                    print(f"{device['name']} Memory usage is OK - {device['system-stats']['mem']}%")
                
    exit(check_status)




## Handles arguments and runs the right subprogram
if args.test == ['check_adopted_devices']:
    check_adopted_devices()
elif args.test == ['check_upgrade_status']:
    check_upgrade_status()
elif args.test == ['check_support_status']:
    check_support_status()
elif args.test == ['check_failover_status']:
    check_failover_status()
elif args.test == ['check_devices_overheating_status']:
    check_devices_overheating_status()
elif args.test == ['check_device_temperatures']:
    check_device_temperatures()
elif args.test == ['check_devices_cpu_status']:
    check_devices_cpu_status()
elif args.test == ['check_devices_mem_status']:
    check_devices_mem_status()
