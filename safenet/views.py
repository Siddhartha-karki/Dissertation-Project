#author
#necessary libraries and modules
from django.shortcuts import render, redirect
import socket
import pywifi
from pywifi import const
import requests

#list of known networks for fake access portal detection
known_networks = [
    {'ssid': 'Test_WIFI', 'bssid': 'c0:05:c2:4d:14:e7'},
    {'ssid': 'Test_WIFI2', 'bssid': '86:0b:7c:60:e6:70'},
    
    

    # this list is for code logic demonstration only and the network information are from the simulated test networks.
]

#function to get the local IP address of the host machine
def get_ip_address():
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    print(ip_address)
    return ip_address

#function to check chosen SSID and BSSID with given list of networks.
def check_ap(chosen_ssid, chosen_bssid):
    for network in known_networks:
        if network['ssid'] == chosen_ssid and network['bssid'] == chosen_bssid:
            return True
    return False

#function to check open ports on the ip address with the list of common ports.
def check_ports(bssid, ip_address):
    target_ip = ip_address
    open_ports = []
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389]

    for port in common_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target_ip, port))
        print("result for port {}: {}".format(port, result))
        if result == 0:
            print("Port {} is open!".format(port))
            open_ports.append(port)
        else:
            print("Port {} is closed.".format(port))
        sock.close()

    return open_ports

# function to check overall network information
def check_wifi_safety():
    try:
        wifi = pywifi.PyWiFi()
        print("Scan Results>>>>", wifi)
        iface = wifi.interfaces()[0]
        print("Checking", iface)
        if len(wifi.interfaces()) == 0:
            print("No WiFi interfaces available.")
            return []
        elif iface.status() != const.IFACE_CONNECTED:
            print("WiFi interface is not connected.")
            return []
        else:
            connected = True
        try:
            scan_results = iface.scan_results()
        except Exception as e:
            print("Error while scanning:", e)
            return []

        scan_results = iface.scan_results()
        print("Scan Results>>>>", scan_results)

        wifi_list = []
        new_ssid = 0
        new_bssid = 0
        ssid = 0
        bssid = 0



        for result in scan_results:
            ssid = result.ssid
            bssid = result.bssid
            signal_strength = result.signal
            
            encryption_type = result.akm[0]
            secured = (encryption_type ==
                       const.AKM_TYPE_WPA2 or encryption_type == const.AKM_TYPE_WPA2PSK or encryption_type == const.AKM_TYPE_WPAPSK)
            # Check for weak signal strength, ideal strength threshold kept to 70 dbm.
            weak_signal = signal_strength < -70

            # Check for open networks (no encryption)
            open_network = encryption_type == const.AKM_TYPE_NONE

        new_bssid = bssid[:-1]
        new_ssid = ssid[:-1]
        print("new_bssid", new_bssid)
        print("new_ssid", new_ssid)

        print("bssid", bssid)
        print("ssid", ssid)


        wifi_list.append({
            'connected': connected,
            'ssid': new_ssid,
            'bssid': new_bssid,
            'secured': secured,
            'signal_strength': signal_strength,
            'weak_signal': weak_signal,
            'open_network': open_network,
        })

        ip_address = get_ip_address()
        open_ports = check_ports(wifi_list[0]['bssid'], ip_address)
        wifi_list[0]['open_ports'] = open_ports
        checkap = check_ap(wifi_list[0]['ssid'],wifi_list[0]['bssid'])
        wifi_list[0]['check_ap'] = checkap

        print(wifi_list)
        return [wifi_list[0]]
    except Exception as e:
        print("Something went wrong while scanning:", e)
        return []

# function to render the learn more page after result.
def learn_more(request):
    return render(request, 'learn_more.html')

#rendering function for the home page.
def home(request):
    ip_address = get_ip_address()
    error_message = None
    connected_network = None
    context = {
            'ip_address': ip_address,
            'wifi_list': [],
            'error_message': error_message,
            'connected_network': connected_network
        }
    return render(request, 'safenet_scan.html', context)
    

# function for fake captive portal detection
def check_fake_captive_portal(request):
    if request.method == 'POST':
        login_url = request.POST.get('login_url')
        is_captive_portal = detect_fake_captive_portal(login_url)
        print(is_captive_portal)
        context = {'is_captive_portal': is_captive_portal}

        return render(request, 'fake_captive_portal.html', context)
    else:
        return render(request, 'fake_captive_portal.html')

# fake captive portal detection through the list of keyworks in the HTML content.
def detect_fake_captive_portal(url):
    try:
        response = requests.get(url)
        html_content = response.text

        keywords = ['login', 'captive', 'portal']

        for keyword in keywords:
            if keyword in html_content.lower():
                return True

        return False
    except Exception as e:
        return False

# function to get check the connectivity.
def get_connected_wifi():
    wifi = pywifi.PyWiFi()
    iface = wifi.interfaces()[0]
    scan_results = iface.scan_results()
    if len(wifi.interfaces()) == 0:
        print("No WiFi interfaces available.")
        return []
    elif iface.status() != const.IFACE_CONNECTED:
        print("WiFi interface is not connected.")
        return []
    try:
        scan_results = iface.scan_results()
    except Exception as e:
        print("Error while scanning:", e)
        return []
    for result in scan_results:
        connected_ssid = result.ssid if scan_results else None
        if connected_ssid:
            connected_bssid = result.bssid if scan_results else None
            return {'ssid': connected_ssid, 'bssid': connected_bssid}
        else:
            return None

# Logic to run the scan now function and render safenet page.
def safenet(request):
    error_message = None
    connected_network = None
    

    try:      
        ip_address = get_ip_address()
        open_ports = check_ports('',ip_address)
        wifi_list = check_wifi_safety()
        connected_network = get_connected_wifi()

    except Exception as e:
        error_message = "Wifi is not connected, please connect to the network!"
        wifi_list = []

    if request.method == 'POST':

        
        print("openport", open_ports)
        if len(wifi_list) == 0 and error_message:
            context = {
                'ip_address': ip_address,
                
                'wifi_list': wifi_list,
                'error_message': error_message,
                'connected_network': connected_network,
                'open_ports': open_ports,
            }
        elif len(wifi_list) == 0:
            context = {
                'ip_address': ip_address,
                'wifi_list': wifi_list,
                'error_message': "Wifi is not connected, please connect to the network!",
                'connected_network': connected_network,
                'open_ports': open_ports,

            }
        else:
            context = {
                'ip_address': ip_address,
                'wifi_list': wifi_list,
                'error_message': error_message,
                'connected_network': connected_network,
                'open_ports': open_ports,
            }

        return render(request, 'safenet_results.html', context)
     