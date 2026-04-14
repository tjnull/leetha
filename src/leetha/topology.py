"""Network topology graph builder.

Builds a hierarchical graph reflecting actual network infrastructure:
  Internet → Router/Gateway → Core Switch → Switches/APs → Clients

Uses LLDP/CDP neighbor data for known links, ARP traffic volume to
infer the core switch, and connection type to route wireless clients
through APs and wired clients through switches.
"""
from __future__ import annotations

import ipaddress
import logging

logger = logging.getLogger(__name__)

_INFRA_TYPES = frozenset({
    "router", "switch", "access_point", "firewall",
    "gateway", "load_balancer", "mesh_router",
    "network_device", "wireless_bridge", "cable_modem",
})

# Normalize non-standard device_type strings to canonical forms
_DEVICE_TYPE_NORMALIZE: dict[str, str] = {
    # --- Capitalization variants ---
    "Router": "router",
    "Switch": "switch",
    "Computer": "workstation",
    "computer": "workstation",
    "Printer": "printer",
    "Server": "server",

    # --- Ubiquiti product lines ---
    "UniFi Switch": "switch",
    "UniFi AP": "access_point",
    "UniFi Gateway": "router",
    "UniFi Dream Machine": "router",
    "UniFi Dream Machine Pro": "router",
    "UniFi Dream Machine Pro Max": "router",
    "UniFi Dream Machine Pro SE": "router",
    "UniFi Dream Machine SE": "router",
    "UniFi Dream Router": "router",
    "UniFi Cloud Gateway": "router",
    "UniFi Security Gateway": "router",
    "EdgeRouter": "router",
    # UniFi Access Point models — Wi-Fi 6 series
    "U6 Lite": "access_point",
    "U6 LR": "access_point",
    "U6 Pro": "access_point",
    "U6 Enterprise": "access_point",
    "U6 Mesh": "access_point",
    "U6 In-Wall": "access_point",
    "U6 Enterprise In-Wall": "access_point",
    "U6 Extender": "access_point",
    "U6+": "access_point",
    # UniFi Access Point models — Wi-Fi 7 series
    "U7 Pro": "access_point",
    "U7 Pro Max": "access_point",
    "U7 Pro Wall": "access_point",
    "U7 Outdoor": "access_point",
    # UniFi Access Point models — legacy UAP series
    "UAP": "access_point",
    "UAP-AC-Lite": "access_point",
    "UAP-AC-LR": "access_point",
    "UAP-AC-Pro": "access_point",
    "UAP-AC-EDU": "access_point",
    "UAP-AC-HD": "access_point",
    "UAP-AC-SHD": "access_point",
    "UAP-AC-Mesh": "access_point",
    "UAP-AC-Mesh-Pro": "access_point",
    "UAP-AC-IW": "access_point",
    "UAP-AC-IW-Pro": "access_point",
    "UAP-IW-HD": "access_point",
    "UAP-nanoHD": "access_point",
    "UAP-FlexHD": "access_point",
    "UAP-BeaconHD": "access_point",
    "nanoHD": "access_point",
    "FlexHD": "access_point",
    "BeaconHD": "access_point",
    # UniFi Building Bridge
    "UBB": "wireless_bridge",
    "UniFi Building Bridge": "wireless_bridge",
    "UniFi Protect": "camera",
    "UniFi Door Access": "smart_lock",
    "G4 Doorbell": "doorbell",
    "G4 Bullet": "camera",
    "G4 Dome": "camera",
    "G4 Pro": "camera",
    "G4 Instant": "camera",
    "G3 Instant": "camera",
    "G3 Flex": "camera",
    "G5 Pro": "camera",
    "G5 Bullet": "camera",
    "G5 Turret": "camera",

    # --- Google / Nest — Smart Speakers ---
    "Google Home": "smart_speaker",
    "Google Home Mini": "smart_speaker",
    "Google Home Max": "smart_speaker",
    "Google Nest Mini": "smart_speaker",
    "Nest Mini": "smart_speaker",
    "Nest Audio": "smart_speaker",

    # --- Google / Nest — Smart Displays ---
    "Google Home Hub": "smart_display",
    "Nest Hub": "smart_display",
    "Nest Hub Max": "smart_display",

    # --- Google / Nest — Streaming Devices ---
    "Chromecast": "streaming_device",
    "Chromecast Audio": "streaming_device",
    "Chromecast Ultra": "streaming_device",
    "Chromecast with Google TV": "streaming_device",
    "Google TV Streamer": "streaming_device",

    # --- Google / Nest — Cameras ---
    "Nest Cam": "camera",
    "Nest Cam Indoor": "camera",
    "Nest Cam Outdoor": "camera",
    "Nest Cam IQ": "camera",
    "Nest Cam IQ Indoor": "camera",
    "Nest Cam IQ Outdoor": "camera",
    "Nest Cam Floodlight": "camera",
    "Dropcam": "camera",
    "Dropcam HD": "camera",
    "Dropcam Pro": "camera",

    # --- Google / Nest — Doorbells ---
    "Nest Doorbell": "doorbell",
    "Nest Hello": "doorbell",

    # --- Google / Nest — Thermostats ---
    "Nest Thermostat": "thermostat",
    "Nest Learning Thermostat": "thermostat",
    "Nest Thermostat E": "thermostat",

    # --- Google / Nest — Routers ---
    "Google Wifi": "mesh_router",
    "Nest Wifi": "mesh_router",
    "Nest Wifi Router": "mesh_router",
    "Nest Wifi Point": "mesh_router",
    "Nest Wifi Pro": "mesh_router",

    # --- Google / Nest — Safety & Security ---
    "Nest Protect": "smart_home",
    "Nest Secure": "smart_home",
    "Nest Guard": "smart_home",
    "Nest Connect": "smart_home",
    "Nest x Yale Lock": "smart_lock",

    # --- Google — Phones ---
    "Pixel": "smartphone",
    "Pixel Phone": "smartphone",

    # --- Google — Tablets ---
    "Pixel Tablet": "tablet",
    "Pixel C": "tablet",
    "Pixel Slate": "tablet",

    # --- Google — Wearables ---
    "Pixel Watch": "wearable",
    "Pixel Buds": "wearable",

    # --- Other phone brands ---
    "OnePlus": "smartphone",
    "Xiaomi": "smartphone",
    "Redmi": "smartphone",
    "POCO": "smartphone",
    "Huawei": "smartphone",
    "Honor": "smartphone",
    "OPPO": "smartphone",
    "Realme": "smartphone",
    "Vivo": "smartphone",
    "Motorola": "smartphone",
    "Moto G": "smartphone",
    "Moto E": "smartphone",
    "Nokia": "smartphone",
    "Xperia": "smartphone",
    "ZTE": "smartphone",
    "Nothing Phone": "smartphone",
    "Fairphone": "smartphone",
    "ROG Phone": "smartphone",

    # --- Other tablets ---
    "Lenovo Tab": "tablet",
    "MatePad": "tablet",
    "Xiaomi Pad": "tablet",
    "Redmi Pad": "tablet",

    # --- Google — Laptops ---
    "Pixelbook": "laptop",
    "Pixelbook Go": "laptop",
    "Chromebook Pixel": "laptop",

    # --- Fitbit (now Google) ---
    "Fitbit": "wearable",
    "Fitbit Aria": "iot",       # WiFi scale
    "Fitbit Aria 2": "iot",     # WiFi scale

    # --- Amazon — Smart Speakers ---
    "Echo": "smart_speaker",
    "Echo Dot": "smart_speaker",
    "Echo Pop": "smart_speaker",
    "Echo Studio": "smart_speaker",

    # --- Amazon — Smart Displays ---
    "Echo Show": "smart_display",

    # --- Amazon — Streaming ---
    "Fire TV": "streaming_device",
    "Fire TV Stick": "streaming_device",
    "Fire TV Cube": "streaming_device",
    # --- Amazon — Tablets & Readers ---
    "Fire Tablet": "tablet",
    "Fire HD": "tablet",
    "Fire Max": "tablet",
    "Kindle": "tablet",
    "Kindle Paperwhite": "tablet",
    "Kindle Oasis": "tablet",
    "Kindle Scribe": "tablet",

    # --- Amazon — Doorbells & Cameras ---
    "Ring Doorbell": "doorbell",
    "Ring Video Doorbell": "doorbell",
    "Ring Cam": "camera",
    "Ring Indoor Cam": "camera",
    "Ring Stick Up Cam": "camera",
    "Ring Spotlight Cam": "camera",
    "Ring Floodlight Cam": "camera",
    "Blink": "camera",
    "Blink Mini": "camera",
    "Blink Outdoor": "camera",

    # --- Apple ---
    "HomePod": "smart_speaker",
    "HomePod Mini": "smart_speaker",
    "HomePod mini": "smart_speaker",
    "Apple TV": "streaming_device",
    "Apple Vision Pro": "wearable",
    "AirPort Extreme": "router",
    "AirPort Express": "access_point",
    "Time Capsule": "nas",
    "iPod touch": "smartphone",

    # --- Virtualization / Containers ---
    "virtual_machine": "server",
    "vm": "server",
    "esxi": "server",
    "proxmox": "server",
    "hypervisor": "server",
    "hyper_v": "server",
    "kvm_host": "server",
    "xen": "server",
    "container_host": "server",
    "docker_host": "server",
    "kubernetes_node": "server",
    "openshift": "server",

    # --- Network infrastructure ---
    "industrial_switch": "switch",
    "network": "switch",
    "proxy": "server",
    "cable_modem": "cable_modem",
    "wireless_bridge": "access_point",
    "wan_optimizer": "network_device",
    "av_switcher": "av_switcher",

    # --- Firewall / Router model names (in case used as device_type) ---
    "FortiGate": "firewall",
    "FortiWiFi": "firewall",
    "PA-Series": "firewall",
    "PA-220": "firewall",
    "PA-440": "firewall",
    "PA-820": "firewall",
    "PA-3200": "firewall",
    "PA-5200": "firewall",
    "Meraki MX": "router",
    "Meraki MR": "access_point",
    "Meraki MS": "switch",
    "SonicWall TZ": "firewall",
    "SonicWall NSA": "firewall",
    "SonicWall NSsp": "firewall",
    "ASA Firewall": "firewall",
    "SRX Firewall": "firewall",
    "WatchGuard Firebox": "firewall",

    # --- Industrial specifics ---
    "cnc_machine": "cnc_machine",
    "power_meter": "power_meter",
    "fire_alarm": "fire_alarm",
    "elevator_controller": "elevator_controller",
    "load_balancer": "load_balancer",
    "ids_ips": "firewall",
    "siem": "server",

    # --- IoT / ICS / SCADA ---
    "microcontroller": "iot",
    "robot_vacuum": "robot_vacuum",
    "health_device": "iot",
    "medical_device": "iot",
    "sensor": "iot",
    "plc": "iot",
    "rtu": "iot",
    "hmi": "iot",
    "building_automation": "iot",
    "iot_gateway": "smart_home",

    # --- Office / Enterprise ---
    "voip_phone": "voip_phone",
    "pbx": "server",
    "multifunction": "printer",
    "thin_client": "workstation",
    "media_server": "server",
    "storage_array": "nas",
    "home_hub": "smart_home",

    # --- Samsung ---
    "Galaxy": "smartphone",
    "Galaxy S": "smartphone",
    "Galaxy Z": "smartphone",
    "Galaxy A": "smartphone",
    "Galaxy M": "smartphone",
    "Galaxy Tab": "tablet",
    "Galaxy Tab S": "tablet",
    "Galaxy Tab A": "tablet",
    "Galaxy Watch": "wearable",
    "Galaxy Buds": "wearable",
    "Samsung Smart TV": "smart_tv",
    "The Frame": "smart_tv",
    "The Freestyle": "smart_tv",
    "SmartThings Hub": "smart_home",
    "Samsung Family Hub": "smart_home",
    "Jet Bot": "iot",

    # --- LG ---
    "LG Smart TV": "smart_tv",
    "LG ThinQ": "smart_home",

    # --- Sony ---
    "Sony Bravia": "smart_tv",

    # --- Microsoft ---
    "Surface": "laptop",
    "Surface Pro": "tablet",
    "Surface Go": "tablet",

    # --- Gaming ---
    "PlayStation": "game_console",
    "PlayStation 3": "game_console",
    "PlayStation 4": "game_console",
    "PlayStation 5": "game_console",
    "PS Vita": "game_console",
    "PlayStation Portal": "game_console",
    "Xbox": "game_console",
    "Xbox 360": "game_console",
    "Xbox One": "game_console",
    "Xbox Series": "game_console",
    "Nintendo Switch": "game_console",
    "Nintendo Wii": "game_console",
    "Nintendo 3DS": "game_console",
    "Nintendo": "game_console",
    "Steam Deck": "game_console",
    "NVIDIA Shield": "streaming_device",

    # --- Sonos ---
    "Sonos One": "smart_speaker",
    "Sonos Beam": "smart_speaker",
    "Sonos Arc": "smart_speaker",
    "Sonos Roam": "smart_speaker",
    "Sonos Move": "smart_speaker",
    "Sonos Era": "smart_speaker",
    "Sonos Play": "smart_speaker",
    "Sonos Port": "streaming_device",
    "Sonos Sub": "smart_speaker",

    # --- Bose ---
    "Bose SoundTouch": "smart_speaker",
    "Bose Soundbar": "smart_speaker",
    "Bose Home Speaker": "smart_speaker",
    "Bose Portable": "smart_speaker",

    # --- Other audio ---
    "JBL": "smart_speaker",
    "Marshall": "smart_speaker",
    "Harman Kardon": "smart_speaker",
    "Denon HEOS": "smart_speaker",
    "Bang & Olufsen": "smart_speaker",

    # --- Appliances ---
    "Family Hub": "appliance",
    "Samsung Fridge": "appliance",
    "Samsung Washer": "appliance",
    "Samsung Dryer": "appliance",
    "LG ThinQ": "appliance",

    # --- Video Conferencing ---
    "Poly Studio": "video_conferencing",
    "Logitech Rally": "video_conferencing",
    "Logitech MeetUp": "video_conferencing",
    "Neat Bar": "video_conferencing",
    "Neat Board": "video_conferencing",
    "Neat Frame": "video_conferencing",
    "Zoom Rooms": "video_conferencing",
    "Microsoft Teams Room": "video_conferencing",
    "Webex Board": "video_conferencing",
    "Webex Room": "video_conferencing",

    # --- Projectors ---
    "Epson Projector": "projector",
    "BenQ Projector": "projector",

    # --- 3D Printers ---
    "Bambu Lab": "3d_printer",
    "Prusa": "3d_printer",
    "Creality": "3d_printer",
    "OctoPrint": "3d_printer",

    # --- UPS ---
    "APC UPS": "ups",
    "APC Smart-UPS": "ups",
    "CyberPower UPS": "ups",
    "Eaton UPS": "ups",

    # --- EV Chargers ---
    "Tesla Wall Connector": "ev_charger",
    "ChargePoint": "ev_charger",
    "Wallbox": "ev_charger",
    "JuiceBox": "ev_charger",
    "Grizzl-E": "ev_charger",
    "Emporia EV": "ev_charger",

    # --- Solar / Energy ---
    "Enphase": "solar_inverter",
    "SolarEdge": "solar_inverter",
    "Tesla Powerwall": "solar_inverter",
    "Tesla Gateway": "solar_inverter",
    "SunPower": "solar_inverter",
    "Generac PWRcell": "solar_inverter",

    # --- Irrigation ---
    "Rachio": "irrigation",
    "RainMachine": "irrigation",
    "Orbit B-hyve": "irrigation",

    # --- Garage ---
    "myQ": "garage_door",
    "LiftMaster": "garage_door",
    "Chamberlain": "garage_door",

    # --- Smoke / Safety ---
    "Nest Protect": "smoke_detector",
    "First Alert OneLink": "smoke_detector",
    "Kidde": "smoke_detector",

    # --- Air Quality ---
    "Dyson Pure": "air_purifier",
    "Molekule": "air_purifier",
    "Coway": "air_purifier",
    "Levoit": "air_purifier",
    "Blueair": "air_purifier",

    # --- Baby / Pet ---
    "Nanit": "baby_monitor",
    "Owlet": "baby_monitor",
    "Miku": "baby_monitor",
    "Petcube": "pet_device",
    "Furbo": "pet_device",

    # --- Digital Signage ---
    "BrightSign": "digital_signage",

    # --- POS ---
    "Square Terminal": "pos_terminal",
    "Toast": "pos_terminal",
    "Clover": "pos_terminal",

    # --- Media Server ---
    "Plex Media Server": "media_server",

    # --- Drones ---
    "DJI": "drone",

    # --- Vehicles ---
    "Tesla": "vehicle",
    "Rivian": "vehicle",
    "Lucid": "vehicle",

    # --- Vehicle Diagnostics ---
    "ELM327": "vehicle_diagnostic",
    "OBDLink": "vehicle_diagnostic",
    "Autel MaxiSys": "vehicle_diagnostic",
    "Launch X431": "vehicle_diagnostic",

    # --- Dashcams ---
    "BlackVue": "dashcam",
    "Viofo": "dashcam",
    "Thinkware": "dashcam",
    "Nextbase": "dashcam",

    # --- Marine ---
    "Raymarine": "marine_device",
    "Simrad": "marine_device",
    "Furuno": "marine_device",

    # --- Satellite / Connectivity ---
    "Starlink": "satellite_terminal",
    "Iridium": "satellite_terminal",
    "Hughes": "satellite_terminal",
    "ViaSat": "satellite_terminal",

    # --- Tactical / Military ---
    "L3Harris": "tactical_radio",
    "Harris Radio": "tactical_radio",
    "Motorola Solutions": "tactical_radio",
    "Persistent Systems MPU5": "tactical_radio",
    "Silvus StreamCaster": "tactical_radio",

    # --- Ruggedized ---
    "Toughbook": "laptop",
    "Getac": "laptop",

    # --- Cross-Domain / Data Diodes ---
    "Owl Cyber Defense": "firewall",
    "Waterfall Security": "firewall",

    # --- Body Cameras ---
    "Axon Body": "body_camera",
    "Axon Fleet": "body_camera",

    # --- Encryption ---
    "KG-175": "crypto_device",
    "TACLANE": "crypto_device",
}

# Vendor → device_type inference when device_type is unknown/generic
_VENDOR_DEVICE_TYPE_HINTS: dict[str, str] = {
    # --- Smart Lighting ---
    "lutron": "smart_lighting",
    "philips hue": "smart_lighting",
    "hue": "smart_lighting",
    "lifx": "smart_lighting",
    "sengled": "smart_lighting",
    "nanoleaf": "smart_lighting",
    "wiz": "smart_lighting",
    "cree": "smart_lighting",
    # --- Smart Speakers / Audio ---
    "sonos": "smart_speaker",
    "bose": "smart_speaker",
    "jbl": "smart_speaker",
    "harman kardon": "smart_speaker",
    "harman": "smart_speaker",
    "marshall": "smart_speaker",
    "bang & olufsen": "smart_speaker",
    "denon": "smart_speaker",
    "yamaha musiccast": "smart_speaker",
    "hui zhou gaoshengda": "smart_speaker",
    "gaoshengda": "smart_speaker",
    # --- Streaming ---
    "roku": "streaming_device",
    "nvidia": "streaming_device",
    # --- IoT Sensors / Vacuums ---
    "roborock": "robot_vacuum",
    "irobot": "robot_vacuum",
    "ecovacs": "robot_vacuum",
    "espressif": "iot",
    "withings": "iot",
    "tuya": "iot",
    "xiaomi": "iot",
    "meross": "smart_plug",
    # --- Cameras ---
    "arlo": "camera",
    "wyze": "camera",
    "reolink": "camera",
    "hikvision": "camera",
    "dahua": "camera",
    "amcrest": "camera",
    "eufy": "camera",
    "lorex": "camera",
    "swann": "camera",
    "axis": "camera",
    "hanwha": "camera",
    "vivotek": "camera",
    "mobotix": "camera",
    "bosch security": "camera",
    "dropcam": "camera",
    # --- Doorbells ---
    "ring": "doorbell",
    # --- Smart Plugs / Switches ---
    "tp-link": "smart_plug",
    "kasa": "smart_plug",
    "tapo": "smart_plug",
    "shelly": "smart_plug",
    "wemo": "smart_plug",
    "gosund": "smart_plug",
    # --- Smart Locks ---
    "august": "smart_lock",
    "yale": "smart_lock",
    "schlage": "smart_lock",
    "kwikset": "smart_lock",
    "level": "smart_lock",
    # --- Smart Home Hubs ---
    "chamberlain": "smart_home",
    "hubitat": "smart_home",
    "smartthings": "smart_home",
    "wink": "smart_home",
    "home assistant": "smart_home",
    # --- Thermostats ---
    "ecobee": "thermostat",
    "honeywell": "thermostat",
    "emerson": "thermostat",
    "tado": "thermostat",
    # --- NAS ---
    "synology": "nas",
    "qnap": "nas",
    "drobo": "nas",
    "netgear readynas": "nas",
    "asustor": "nas",
    "terramaster": "nas",
    "buffalo": "nas",
    "western digital": "nas",
    "wd": "nas",
    # --- Network Infrastructure ---
    "cisco": "switch",
    "meraki": "switch",
    "aruba": "access_point",
    "ruckus": "access_point",
    "commscope": "access_point",
    "mikrotik": "router",
    "netgate": "firewall",
    "pfsense": "firewall",
    "opnsense": "firewall",
    "fortinet": "firewall",
    "fortigate": "firewall",
    "palo alto": "firewall",
    "sophos": "firewall",
    "watchguard": "firewall",
    "sonicwall": "firewall",
    "juniper": "router",
    "eero": "mesh_router",
    "linksys velop": "mesh_router",
    "orbi": "mesh_router",
    "deco": "mesh_router",
    "amplifi": "mesh_router",
    "tplink": "router",
    "netgear": "router",
    "asus router": "router",
    "ubiquiti": "network_device",
    # --- VoIP ---
    "polycom": "voip_phone",
    "poly": "voip_phone",
    "yealink": "voip_phone",
    "cisco phone": "voip_phone",
    "grandstream": "voip_phone",
    "snom": "voip_phone",
    "avaya": "voip_phone",
    "mitel": "voip_phone",
    "fanvil": "voip_phone",
    "obihai": "voip_phone",
    # --- Gaming ---
    "xbox": "game_console",
    "playstation": "game_console",
    "nintendo": "game_console",
    "valve": "game_console",
    # --- Virtualization / Server ---
    "vmware": "server",
    "proxmox": "server",
    "nutanix": "server",
    "citrix": "server",
    "red hat": "server",
    "hashicorp": "server",
    "docker": "server",
    "kubernetes": "server",
    # --- Multi-product vendors (best guess when no hostname/mDNS clues) ---
    "google": "smart_speaker",  # Nest/Home speakers are most common Google IoT
    "apple": "smartphone",       # iPhones are most common Apple device on networks
    "samsung": "smartphone",     # Galaxy phones are most common Samsung device
    "asus": "workstation",       # ASUS devices without specific type are usually PCs
    "asustek": "workstation",
    "dell": "workstation",
    "lenovo": "workstation",
    "hp": "workstation",
    "hewlett packard": "workstation",
    "intel": "workstation",
    "acer": "workstation",
    "msi": "workstation",
    "gigabyte": "workstation",
    "microsoft": "workstation",
    # --- Phone/Tablet manufacturers ---
    "oneplus": "smartphone",
    "xiaomi": "smartphone",
    "huawei": "smartphone",
    "honor": "smartphone",
    "oppo": "smartphone",
    "realme": "smartphone",
    "vivo": "smartphone",
    "motorola": "smartphone",
    "zte": "smartphone",
    "tcl communication": "smartphone",
    "nothing": "smartphone",
    "fairphone": "smartphone",
    "hmd global": "smartphone",  # Nokia phones
    "sony mobile": "smartphone",
    # --- PC / Workstation vendors ---
    "intel corporate": "workstation",
    "dell inc": "laptop",
    "dell technologies": "laptop",
    "asustek": "workstation",
    "msi": "workstation",
    "gigabyte": "workstation",
    "acer": "workstation",
    "lenovo": "workstation",
    "hewlett": "workstation",
    "hp inc": "workstation",
    "razer": "workstation",
    "alienware": "workstation",
    "microsoft": "workstation",
    "framework": "laptop",
    "system76": "workstation",
    # --- Printers ---
    "brother": "printer",
    "canon": "printer",
    "epson": "printer",
    "lexmark": "printer",
    "ricoh": "printer",
    "xerox": "printer",
    "kyocera": "printer",
    "konica": "printer",
    "sharp": "printer",
    "zebra": "printer",
    # --- Medical ---
    "philips medical": "iot",
    "ge healthcare": "iot",
    "siemens healthineers": "iot",
    # --- More IoT brands ---
    "amazon": "smart_speaker",
    "blink": "camera",
    "eufy": "camera",
    "lorex": "camera",
    "swann": "camera",
    "tuya": "iot",
    "meross": "smart_plug",
    "wemo": "smart_plug",
    "gosund": "smart_plug",
    "nanoleaf": "smart_lighting",
    "sengled": "smart_lighting",
    "tado": "thermostat",
    "honeywell home": "thermostat",
    "irobot": "robot_vacuum",
    "ecovacs": "robot_vacuum",
    "kwikset": "smart_lock",
    "schlage": "smart_lock",
    # --- Appliances ---
    "lg electronics": "appliance",
    "whirlpool": "appliance",
    "ge appliances": "appliance",
    "bosch home": "appliance",
    "miele": "appliance",
    # --- Video Conferencing ---
    "poly": "video_conferencing",
    "neat": "video_conferencing",
    "logitech": "video_conferencing",
    "crestron": "video_conferencing",
    "extron": "video_conferencing",
    # --- Projectors ---
    "epson": "projector",
    "benq": "projector",
    "optoma": "projector",
    "viewsonic": "projector",
    # --- 3D Printers ---
    "bambu lab": "3d_printer",
    "prusa": "3d_printer",
    "creality": "3d_printer",
    # --- UPS / Power ---
    "apc": "ups",
    "cyberpower": "ups",
    "eaton": "ups",
    "tripp lite": "ups",
    "raritan": "ups",
    # --- EV Chargers ---
    "chargepoint": "ev_charger",
    "wallbox": "ev_charger",
    "juicebox": "ev_charger",
    "emporia": "ev_charger",
    "grizzl-e": "ev_charger",
    "clipper creek": "ev_charger",
    # --- Solar ---
    "enphase": "solar_inverter",
    "solaredge": "solar_inverter",
    "sunpower": "solar_inverter",
    "generac": "solar_inverter",
    # --- Irrigation ---
    "rachio": "irrigation",
    "rainmachine": "irrigation",
    "orbit": "irrigation",
    "hunter": "irrigation",
    # --- Garage ---
    "chamberlain": "garage_door",
    "liftmaster": "garage_door",
    # --- Air Quality ---
    "dyson": "air_purifier",
    "molekule": "air_purifier",
    "coway": "air_purifier",
    "levoit": "air_purifier",
    "blueair": "air_purifier",
    # --- Baby / Pet ---
    "nanit": "baby_monitor",
    "owlet": "baby_monitor",
    "petcube": "pet_device",
    "furbo": "pet_device",
    # --- Digital Signage ---
    "brightsign": "digital_signage",
    "scala": "digital_signage",
    # --- POS ---
    "square": "pos_terminal",
    "toast": "pos_terminal",
    "clover": "pos_terminal",
    "verifone": "pos_terminal",
    "ingenico": "pos_terminal",
    # --- Drones ---
    "dji": "drone",
    "parrot": "drone",
    "skydio": "drone",
    # --- Vehicles ---
    "tesla": "vehicle",
    "rivian": "vehicle",
    "lucid motors": "vehicle",
    # --- Vehicle Diagnostics ---
    "autel": "vehicle_diagnostic",
    "launch tech": "vehicle_diagnostic",
    "scantool": "vehicle_diagnostic",
    # --- Dashcams ---
    "blackvue": "dashcam",
    "pittasoft": "dashcam",
    "viofo": "dashcam",
    "thinkware": "dashcam",
    "nextbase": "dashcam",
    "garmin dash": "dashcam",
    "rexing": "dashcam",
    "vantrue": "dashcam",
    # --- Marine ---
    "garmin marine": "marine_device",
    "raymarine": "marine_device",
    "simrad": "marine_device",
    "navico": "marine_device",
    "furuno": "marine_device",
    "vesper marine": "marine_device",
    "victron": "marine_device",
    "pepwave": "router",
    "peplink": "router",
    # --- Fleet / GPS ---
    "calamp": "gps_tracker",
    "geotab": "gps_tracker",
    "samsara": "gps_tracker",
    "queclink": "gps_tracker",
    "sierra wireless": "router",
    "cradlepoint": "router",
    # --- Satellite ---
    "starlink": "satellite_terminal",
    "spacex": "satellite_terminal",
    "hughesnet": "satellite_terminal",
    "viasat": "satellite_terminal",
    "iridium": "satellite_terminal",
    # --- Tactical / Military ---
    "l3harris": "tactical_radio",
    "harris corporation": "tactical_radio",
    "motorola solutions": "tactical_radio",
    "general dynamics": "tactical_radio",
    "persistent systems": "tactical_radio",
    "silvus": "tactical_radio",
    "thales": "tactical_radio",
    # --- Ruggedized ---
    "getac": "laptop",
    "panasonic toughbook": "laptop",
    "panasonic connect": "laptop",
    "sonim": "smartphone",
    # --- Satellite ---
    "idirect": "satellite_terminal",
    "cobham": "satellite_terminal",
    # --- Cross-Domain ---
    "owl cyber": "firewall",
    "waterfall security": "firewall",
    "forcepoint": "firewall",
    # --- Body Cameras ---
    "axon": "body_camera",
    "motorola body": "body_camera",
    # --- Weather ---
    "davis instruments": "weather_station",
    "acurite": "weather_station",
    "ambient weather": "weather_station",
    # --- Lab Instruments ---
    "keysight": "lab_instrument",
    "tektronix": "lab_instrument",
    "rigol": "lab_instrument",
    "rohde & schwarz": "lab_instrument",
    "national instruments": "lab_instrument",
    # --- Interactive Displays ---
    "smart technologies": "interactive_display",
    "promethean": "interactive_display",
    # --- Time Clocks ---
    "kronos": "time_clock",
    "adp": "time_clock",
    # --- Single Board Computers ---
    "raspberry pi": "sbc",
    # --- ATM ---
    "diebold": "atm",
    "ncr": "atm",
    "wincor nixdorf": "atm",
    # --- Vending ---
    "cantaloupe": "vending_machine",
    "crane": "vending_machine",
    # --- Barcode Scanners ---
    "zebra technologies": "handheld_scanner",
    "honeywell scanning": "handheld_scanner",
    "datalogic": "handheld_scanner",
    # --- Wireless Presentation ---
    "barco": "wireless_presentation",
    "clickshare": "wireless_presentation",
    "mersive": "wireless_presentation",
    "kramer": "wireless_presentation",
    # --- Access Control ---
    "hid global": "access_control",
    "lenel": "access_control",
    "genetec": "access_control",
    "avigilon": "access_control",
    # --- Industrial ---
    "siemens": "plc",
    "allen-bradley": "plc",
    "rockwell": "plc",
    "schneider electric": "plc",
    "omron": "plc",
    "beckhoff": "plc",
    "moxa": "industrial_switch",
    "hirschmann": "industrial_switch",
    "advantech": "industrial_switch",
    "phoenix contact": "industrial_switch",
    "wago": "plc",
    "fanuc": "industrial_robot",
    "abb robotics": "industrial_robot",
    "kuka": "industrial_robot",
    "universal robots": "industrial_robot",
    "yaskawa": "industrial_robot",
    "doosan robotics": "industrial_robot",
    # --- CNC ---
    "haas": "cnc_machine",
    "mazak": "cnc_machine",
    "okuma": "cnc_machine",
    "dmg mori": "cnc_machine",
    "heidenhain": "cnc_machine",
    "hurco": "cnc_machine",
    # --- Power Meters ---
    "accuenergy": "power_meter",
    "dent instruments": "power_meter",
    "electro industries": "power_meter",
    "satec": "power_meter",
    "itron": "power_meter",
    "landis+gyr": "power_meter",
    # --- Fire Alarm ---
    "notifier": "fire_alarm",
    "simplex": "fire_alarm",
    "edwards est": "fire_alarm",
    "hochiki": "fire_alarm",
    "fike": "fire_alarm",
    "gamewell": "fire_alarm",
    # --- Elevator ---
    "otis": "elevator_controller",
    "schindler": "elevator_controller",
    "thyssenkrupp": "elevator_controller",
    "kone": "elevator_controller",
    # --- Building Automation ---
    "johnson controls": "building_automation",
    "tridium": "building_automation",
    "distech": "building_automation",
    "automated logic": "building_automation",
    # --- Medical ---
    "ge healthcare": "medical_device",
    "philips healthcare": "medical_device",
    "medtronic": "medical_device",
    "baxter": "medical_device",
    "bd": "medical_device",
    "hill-rom": "medical_device",
    "stryker": "medical_device",
    "draeger": "medical_device",
    "nihon kohden": "medical_device",
    "mindray": "medical_device",
    "icu medical": "medical_device",
    "fresenius": "medical_device",
    "b. braun": "medical_device",
    "ascom": "medical_device",
    # --- Nurse Call ---
    "rauland": "medical_device",
    # --- Kiosk / POS ---
    "ncr": "kiosk",
    "diebold nixdorf": "kiosk",
    "wincor nixdorf": "kiosk",
    "toshiba tec": "pos_terminal",
    "fujitsu": "kiosk",
    # --- AV / Room Control ---
    "crestron": "video_conferencing",
    "control4": "smart_home",
    "savant": "smart_home",
    # --- Badge Printers ---
    "evolis": "printer",
    "hid fargo": "printer",
    "entrust datacard": "printer",
    "sato": "printer",
    "dymo": "printer",
    # --- IPTV ---
    "amino": "streaming_device",
    "zeevee": "streaming_device",
    "enseo": "streaming_device",
    # --- AV Controllers ---
    "extron": "video_conferencing",
    "amx": "video_conferencing",
    "qsc": "video_conferencing",
    "biamp": "video_conferencing",
    # --- Lab Instruments ---
    "keysight": "lab_instrument",
    "agilent": "lab_instrument",
    "tektronix": "lab_instrument",
    "rigol": "lab_instrument",
    "siglent": "lab_instrument",
    "rohde & schwarz": "lab_instrument",
    "anritsu": "lab_instrument",
    "yokogawa": "lab_instrument",
    # --- Weather Stations ---
    "davis instruments": "weather_station",
    "acurite": "weather_station",
    "ambient weather": "weather_station",
    "ecowitt": "weather_station",
    "la crosse": "weather_station",
    "weatherflow": "weather_station",
    # --- Interactive Displays ---
    "smart technologies": "interactive_display",
    "promethean": "interactive_display",
    "newline": "interactive_display",
    # --- Telescope ---
    "celestron": "lab_instrument",
    "meade": "lab_instrument",
    "sky-watcher": "lab_instrument",
    "ioptron": "lab_instrument",
}


def _normalize_device_type(dt: str | None) -> str:
    if not dt:
        return "unknown"
    if dt in _DEVICE_TYPE_NORMALIZE:
        return _DEVICE_TYPE_NORMALIZE[dt]
    dt_lower = dt.lower()
    if dt_lower in _DEVICE_TYPE_NORMALIZE:
        return _DEVICE_TYPE_NORMALIZE[dt_lower]
    # Firewall brand/model keywords (check before switch to avoid "av_switcher" false positive)
    if any(k in dt_lower for k in ("firewall", "fortigate", "fortiwifi", "sonicwall",
                                    "watchguard", "firebox", "pfsense", "opnsense",
                                    "pa-series", "pa-2", "pa-3", "pa-4", "pa-5", "pa-8",
                                    "ids_ips", "asa ")):
        return "firewall"
    for keyword in ("switch", "router", "gateway", "dream machine", "edgerouter",
                    "security gateway", "meraki mx"):
        if keyword in dt_lower:
            if "switch" in dt_lower and "dream" not in dt_lower and "av_" not in dt_lower:
                return "switch"
            if any(k in dt_lower for k in ("router", "gateway", "dream machine",
                                            "edgerouter", "security gateway",
                                            "meraki mx")):
                return "router"
    if "cable_modem" in dt_lower:
        return "cable_modem"
    # Check for access point — but "ap" is too short and matches "laptop", "map", etc.
    # Only match if "ap" is a standalone word or part of "access_point"/"access point"
    if "access_point" in dt_lower or "access point" in dt_lower:
        return "access_point"
    if dt_lower in ("ap", "wap") or dt_lower.startswith("ap ") or " ap" in dt_lower:
        return "access_point"
    # Check for doorbell/camera keywords
    if "doorbell" in dt_lower:
        return "doorbell"
    if "camera" in dt_lower or "cam" == dt_lower:
        return "camera"
    return dt_lower


def _infer_type_from_vendor(device_type: str, manufacturer: str | None) -> str:
    """If device_type is unknown/generic, try to infer from manufacturer name."""
    if device_type not in ("unknown", "computer", "workstation", "iot", "nas", "server"):
        return device_type
    if not manufacturer:
        return device_type
    mfr_lower = manufacturer.lower()
    for vendor_pattern, inferred_type in _VENDOR_DEVICE_TYPE_HINTS.items():
        if vendor_pattern in mfr_lower:
            return inferred_type
    return device_type


# Hostname patterns that indicate specific device types
_HOSTNAME_DEVICE_HINTS: list[tuple[str, str]] = [
    # --- Smart displays (must come before "speaker"/"home" catch-alls) ---
    ("nest-hub", "smart_display"),
    ("nest hub", "smart_display"),
    ("nesthub", "smart_display"),
    ("echo-show", "smart_display"),
    ("echo show", "smart_display"),
    # --- Google/Nest speakers ---
    ("google-home-mini", "smart_speaker"),
    ("google-home-max", "smart_speaker"),
    ("google-home", "smart_speaker"),
    ("google-nest-mini", "smart_speaker"),
    ("nest-mini", "smart_speaker"),
    ("nest-audio", "smart_speaker"),
    ("nest audio", "smart_speaker"),
    # --- Google streaming ---
    ("chromecast", "streaming_device"),
    ("google-tv-streamer", "streaming_device"),
    # --- Google cameras ---
    ("nest-cam", "camera"),
    ("nestcam", "camera"),
    ("dropcam", "camera"),
    # --- Google doorbells ---
    ("nest-doorbell", "doorbell"),
    ("nest-hello", "doorbell"),
    # --- Google thermostats ---
    ("nest-thermostat", "thermostat"),
    # --- Google routers ---
    ("google-wifi", "mesh_router"),
    ("nest-wifi", "mesh_router"),
    ("nestwifi", "mesh_router"),
    # --- Google safety ---
    ("nest-protect", "smoke_detector"),
    # --- Google tablets (must come before pixel- phone pattern) ---
    ("pixel-tablet", "tablet"),
    # --- Google phones ---
    ("pixel-", "smartphone"),
    # --- Fitbit ---
    ("fitbit", "wearable"),
    # --- Generic speakers ---
    ("speaker", "smart_speaker"),
    ("homepod", "smart_speaker"),
    ("sonos", "smart_speaker"),
    ("echo-dot", "smart_speaker"),
    ("echo-pop", "smart_speaker"),
    ("echo-studio", "smart_speaker"),
    ("echo", "smart_speaker"),
    ("alexa", "smart_speaker"),
    # --- Amazon ---
    ("fire-tv", "streaming_device"),
    ("firetv", "streaming_device"),
    ("kindle", "tablet"),
    ("fire-hd", "tablet"),
    ("ring-doorbell", "doorbell"),
    ("ring-cam", "camera"),
    ("ring-spotlight", "camera"),
    ("ring-floodlight", "camera"),
    ("ring-stick", "camera"),
    ("ring-indoor", "camera"),
    ("blink-", "camera"),
    ("arlo-", "camera"),
    ("wyze-cam", "camera"),
    ("wyze-doorbell", "doorbell"),
    # --- Generic patterns ---
    ("doorbell", "doorbell"),
    ("camera", "camera"),
    ("cam-", "camera"),
    ("thermostat", "thermostat"),
    ("vacuum", "robot_vacuum"),
    ("roborock", "robot_vacuum"),
    ("printer", "printer"),
    ("nas", "nas"),
    ("proxmox", "server"),
    ("esxi", "server"),
    ("vcenter", "server"),
    ("truenas", "nas"),
    ("freenas", "nas"),
    ("unraid", "nas"),
    ("synology", "nas"),
    ("plex", "media_server"),
    ("home-assistant", "smart_home"),
    ("homeassistant", "smart_home"),
    ("hass", "smart_home"),
    ("openmediavault", "nas"),
    ("omv", "nas"),
    ("hubitat", "smart_home"),
    ("smartthings", "smart_home"),
    ("roku", "streaming_device"),
    ("chromecast", "streaming_device"),
    ("appletv", "streaming_device"),
    ("apple-tv", "streaming_device"),
    ("firetv", "streaming_device"),
    ("fire-tv", "streaming_device"),
    ("ps5-", "game_console"),
    ("ps4-", "game_console"),
    ("ps3-", "game_console"),
    ("playstation", "game_console"),
    ("xbox-systemos", "game_console"),
    ("xbox", "game_console"),
    ("steamdeck", "game_console"),
    ("steam-deck", "game_console"),
    ("shield", "streaming_device"),
    ("nintendo", "game_console"),
    # --- Samsung ---
    ("galaxy-s", "smartphone"),
    ("galaxy-z", "smartphone"),
    ("galaxy-a", "smartphone"),
    ("galaxy-tab", "tablet"),
    ("galaxy-watch", "wearable"),
    ("samsung-tv", "smart_tv"),
    ("tizen", "smart_tv"),
    ("smartthings-hub", "smart_home"),
    ("jet-bot", "iot"),
    # --- Smart TVs ---
    ("lgwebostv", "smart_tv"),
    ("lg-webos", "smart_tv"),
    ("lgsmarttv", "smart_tv"),
    ("bravia", "smart_tv"),
    ("vizio", "smart_tv"),
    ("hisense", "smart_tv"),
    # --- Roku ---
    ("np-", "streaming_device"),  # Roku hostname pattern NP-{serial}
    # --- Sonos ---
    ("sonos-", "smart_speaker"),
    # --- Apple ---
    ("iphone", "smartphone"),
    ("ipod", "smartphone"),
    ("ipad", "tablet"),
    ("macbook-air", "laptop"),
    ("macbook-pro", "laptop"),
    ("macbook", "laptop"),
    ("imac-pro", "workstation"),
    ("imac", "workstation"),
    ("mac-mini", "workstation"),
    ("mac-studio", "workstation"),
    ("mac-pro", "workstation"),
    ("apple-watch", "wearable"),
    ("apple-vision", "wearable"),
    ("homepod", "smart_speaker"),
    ("apple-tv", "streaming_device"),
    ("appletv", "streaming_device"),
    ("airport", "router"),
    ("time-capsule", "nas"),
    # --- Microsoft ---
    ("surface-pro", "tablet"),
    ("surface-go", "tablet"),
    ("surface", "laptop"),
    # --- Other Android phones ---
    ("oneplus", "smartphone"),
    ("one-plus", "smartphone"),
    ("xiaomi-pad", "tablet"),
    ("xiaomi", "smartphone"),
    ("redmi-pad", "tablet"),
    ("redmi", "smartphone"),
    ("poco", "smartphone"),
    ("huawei-matepad", "tablet"),
    ("huawei", "smartphone"),
    ("honor", "smartphone"),
    ("oppo", "smartphone"),
    ("realme", "smartphone"),
    ("vivo", "smartphone"),
    ("motorola", "smartphone"),
    ("moto-g", "smartphone"),
    ("moto-e", "smartphone"),
    ("moto-x", "smartphone"),
    ("nokia-", "smartphone"),
    ("xperia", "smartphone"),
    ("zte", "smartphone"),
    ("tcl-", "smartphone"),
    ("nothing-phone", "smartphone"),
    ("fairphone", "smartphone"),
    ("asus-rog-phone", "smartphone"),
    ("lg-v", "smartphone"),
    ("lg-g", "smartphone"),
    # --- Android hostname patterns ---
    ("android-", "smartphone"),  # Default Android DHCP hostname
    ("sm-s", "smartphone"),      # Samsung model codes SM-Sxxx
    ("sm-g", "smartphone"),      # Samsung Galaxy SM-Gxxx
    ("sm-f", "smartphone"),      # Samsung Fold SM-Fxxx
    ("sm-a", "smartphone"),      # Samsung A-series SM-Axxx
    ("sm-t", "tablet"),          # Samsung Tab SM-Txxx
    ("sm-x", "tablet"),          # Samsung Tab SM-Xxxx
    ("sm-p", "tablet"),          # Samsung Tab SM-Pxxx
    # --- Other tablets (patterns not covered in phone section above) ---
    ("lenovo-tab", "tablet"),
    ("tab-m", "tablet"),         # Lenovo Tab M series
    ("tab-p", "tablet"),         # Lenovo Tab P series
    ("huawei-matepad", "tablet"),
    ("matepad", "tablet"),
    ("nokia-t", "tablet"),       # Nokia T-series tablets
    # --- Sonos ---
    ("sonos-", "smart_speaker"),
    # --- Bose ---
    ("bose-", "smart_speaker"),
    # --- Roku ---
    ("roku", "streaming_device"),
    # --- NVIDIA ---
    ("shield", "streaming_device"),
    # --- IoT/Smart Home ---
    ("ecobee", "thermostat"),
    ("roomba", "robot_vacuum"),
    ("roborock", "robot_vacuum"),
    ("dyson-pure", "air_purifier"),
    ("dyson", "air_purifier"),
    # --- Ubiquiti model codes ---
    ("usw-", "switch"),       # UniFi Switch (USW-Pro-24, USW-Flex, etc.)
    ("udm", "router"),        # UniFi Dream Machine
    ("udr", "router"),        # UniFi Dream Router
    ("ucg-", "router"),       # UniFi Cloud Gateway
    ("uxg-", "router"),       # UniFi Next-Gen Gateway
    ("uap-", "access_point"), # UniFi AP (legacy)
    ("u6-", "access_point"),  # UniFi WiFi 6 AP
    ("u7-", "access_point"),  # UniFi WiFi 7 AP
    ("ubb", "wireless_bridge"),  # UniFi Building Bridge
    ("uvc-", "camera"),       # UniFi Protect camera
    ("unvr", "server"),       # UniFi NVR
    ("ubnt", "router"),
    ("unifi", "network_device"),  # UniFi covers APs, switches, gateways — too broad for "switch"
    # --- Cisco Meraki model codes ---
    ("mr-", "access_point"),   # Meraki AP
    ("ms-", "switch"),         # Meraki Switch
    ("mx-", "firewall"),       # Meraki Security Appliance
    ("meraki", "switch"),
    # --- Fortinet model codes ---
    ("fg-", "firewall"),       # FortiGate
    ("fgt-", "firewall"),
    ("fortigate", "firewall"),
    ("fortiswitch", "switch"),
    ("fortiap", "access_point"),
    # --- Palo Alto ---
    ("pa-", "firewall"),       # PA-440, PA-5260, etc.
    # --- Juniper model codes ---
    ("ex-", "switch"),         # EX switches
    ("qfx", "switch"),         # QFX DC switches
    ("srx", "firewall"),       # SRX firewalls
    ("mx-", "router"),         # MX routers (note: also matches Meraki)
    # --- Other infra ---
    ("mikrotik", "router"),
    ("routeros", "router"),
    ("pfsense", "firewall"),
    ("opnsense", "firewall"),
    ("netgate", "firewall"),
    ("sg-", "firewall"),       # Netgate SG-xxxx
    ("ruckus", "access_point"),
    ("icx-", "switch"),        # Ruckus ICX switches
    ("aruba", "access_point"),
    ("procurve", "switch"),
    # --- Mesh routers ---
    ("eero", "mesh_router"),
    ("orbi", "mesh_router"),
    ("velop", "mesh_router"),
    ("deco", "mesh_router"),
    ("amplifi", "mesh_router"),
    # --- TP-Link Omada ---
    ("eap", "access_point"),   # Omada EAP APs
    ("archer", "router"),      # TP-Link consumer routers
    # --- NAS ---
    ("diskstation", "nas"),   # Synology DiskStation
    ("rackstation", "nas"),   # Synology RackStation
    ("flashstation", "nas"),  # Synology FlashStation
    ("synology", "nas"),
    ("ts-", "nas"),           # QNAP TS-xxx models
    ("tvs-", "nas"),          # QNAP TVS models
    ("qnap", "nas"),
    ("readynas", "nas"),      # Netgear ReadyNAS
    ("truenas", "nas"),
    ("freenas", "nas"),
    ("unraid", "nas"),
    ("openmediavault", "nas"),
    ("omv", "nas"),
    # --- Servers ---
    ("proxmox", "server"),
    ("esxi", "server"),
    ("vcenter", "server"),
    ("docker", "server"),
    # --- VoIP ---
    ("polycom", "voip_phone"),
    ("yealink", "voip_phone"),
    ("grandstream", "voip_phone"),
    # --- Printers ---
    ("printer", "printer"),
    ("laserjet", "printer"),
    ("officejet", "printer"),
    ("deskjet", "printer"),
    ("pixma", "printer"),
    ("brother", "printer"),
    ("epson", "printer"),
    # --- Appliances ---
    ("family-hub", "appliance"),
    ("thinq", "appliance"),
    ("smartthinq", "appliance"),
    ("washer", "appliance"),
    ("dryer", "appliance"),
    ("dishwasher", "appliance"),
    ("refrigerator", "appliance"),
    ("oven", "appliance"),
    # --- Video Conferencing ---
    ("poly-studio", "video_conferencing"),
    ("logitech-rally", "video_conferencing"),
    ("logitech-meetup", "video_conferencing"),
    ("neat-bar", "video_conferencing"),
    ("neat-board", "video_conferencing"),
    ("zoom-room", "video_conferencing"),
    ("teams-room", "video_conferencing"),
    ("webex-board", "video_conferencing"),
    ("webex-room", "video_conferencing"),
    # --- Projectors ---
    ("projector", "projector"),
    # --- 3D Printers ---
    ("bambulab", "3d_printer"),
    ("bambu", "3d_printer"),
    ("prusa", "3d_printer"),
    ("octoprint", "3d_printer"),
    ("creality", "3d_printer"),
    ("ender-", "3d_printer"),    # Creality Ender series
    # --- UPS ---
    ("smart-ups", "ups"),
    ("apc-", "ups"),
    ("cyberpower", "ups"),
    # --- EV Chargers ---
    ("chargepoint", "ev_charger"),
    ("wallbox", "ev_charger"),
    ("juicebox", "ev_charger"),
    ("tesla-wall", "ev_charger"),
    # --- Solar ---
    ("enphase", "solar_inverter"),
    ("solaredge", "solar_inverter"),
    ("powerwall", "solar_inverter"),
    ("tesla-gateway", "solar_inverter"),
    # --- Irrigation ---
    ("rachio", "irrigation"),
    ("rainmachine", "irrigation"),
    ("b-hyve", "irrigation"),
    ("sprinkler", "irrigation"),
    # --- Garage ---
    ("myq", "garage_door"),
    ("liftmaster", "garage_door"),
    ("garage", "garage_door"),
    # --- Smoke Detectors ---
    ("onelink", "smoke_detector"),
    # --- Air Purifier ---
    ("dyson-pure", "air_purifier"),
    ("purifier", "air_purifier"),
    ("molekule", "air_purifier"),
    # --- Baby / Pet ---
    ("nanit", "baby_monitor"),
    ("owlet", "baby_monitor"),
    ("baby-monitor", "baby_monitor"),
    ("petcube", "pet_device"),
    ("furbo", "pet_device"),
    # --- Digital Signage ---
    ("brightsign", "digital_signage"),
    # --- POS ---
    ("square-terminal", "pos_terminal"),
    ("clover", "pos_terminal"),
    # --- Media Server ---
    ("plex", "media_server"),
    ("jellyfin", "media_server"),
    ("emby", "media_server"),
    # --- Drones ---
    ("dji-", "drone"),
    # --- Wireless Bridge ---
    ("litebeam", "wireless_bridge"),
    ("nanobeam", "wireless_bridge"),
    ("nanostation", "wireless_bridge"),
    ("powerbeam", "wireless_bridge"),
    # --- Vehicles ---
    ("tesla-model", "vehicle"),
    ("tesla", "vehicle"),
    ("rivian", "vehicle"),
    # --- Vehicle Diagnostics ---
    ("elm327", "vehicle_diagnostic"),
    ("obdlink", "vehicle_diagnostic"),
    ("obd", "vehicle_diagnostic"),
    ("maxisys", "vehicle_diagnostic"),
    # --- Dashcams ---
    ("blackvue", "dashcam"),
    ("viofo", "dashcam"),
    ("thinkware", "dashcam"),
    ("nextbase", "dashcam"),
    ("dashcam", "dashcam"),
    # --- Marine ---
    ("raymarine", "marine_device"),
    ("axiom", "marine_device"),
    ("simrad", "marine_device"),
    ("furuno", "marine_device"),
    ("gpsmap", "marine_device"),
    ("vesper", "marine_device"),
    ("cerbo", "marine_device"),
    ("venus-gx", "marine_device"),
    # --- Satellite ---
    ("starlink", "satellite_terminal"),
    ("hughesnet", "satellite_terminal"),
    ("viasat", "satellite_terminal"),
    # --- Fleet / GPS ---
    ("samsara", "gps_tracker"),
    ("geotab", "gps_tracker"),
    ("airlink", "router"),
    ("cradlepoint", "router"),
    # --- Tactical ---
    ("l3harris", "tactical_radio"),
    ("silvus", "tactical_radio"),
    ("mpu5", "tactical_radio"),
    ("streamcaster", "tactical_radio"),
    ("taclane", "crypto_device"),
    # --- Ruggedized ---
    ("toughbook", "laptop"),
    ("getac-", "laptop"),
    # --- Body Camera ---
    ("axon-body", "body_camera"),
    ("axon-fleet", "body_camera"),
    # --- Weather ---
    ("weather-station", "weather_station"),
    ("acurite", "weather_station"),
    ("davis-vantage", "weather_station"),
    # --- Lab Instruments ---
    ("keysight", "lab_instrument"),
    ("tektronix", "lab_instrument"),
    ("rigol", "lab_instrument"),
    ("oscilloscope", "lab_instrument"),
    # --- Single Board Computers ---
    ("raspberrypi", "sbc"),
    ("raspberry-pi", "sbc"),
    ("raspberry", "sbc"),
    ("pine64", "sbc"),
    ("odroid", "sbc"),
    ("jetson", "sbc"),
    # --- Interactive Displays ---
    ("smart-board", "interactive_display"),
    ("smartboard", "interactive_display"),
    ("promethean", "interactive_display"),
    # --- ATM ---
    ("atm-", "atm"),
    ("diebold", "atm"),
    # --- Vending ---
    ("vending", "vending_machine"),
    # --- Time Clock ---
    ("kronos", "time_clock"),
    ("timeclock", "time_clock"),
    # --- Barcode Scanner ---
    ("zebra-scanner", "handheld_scanner"),
    ("handheld", "handheld_scanner"),
    # --- Wireless Presentation ---
    ("clickshare", "wireless_presentation"),
    ("mersive", "wireless_presentation"),
    ("solstice", "wireless_presentation"),
    # --- Access Control ---
    ("lenel", "access_control"),
    ("genetec", "access_control"),
    ("access-control", "access_control"),
    # --- Industrial PLCs ---
    ("plc-", "plc"),
    ("simatic", "plc"),
    ("s7-1500", "plc"),
    ("s7-1200", "plc"),
    ("controllogix", "plc"),
    ("compactlogix", "plc"),
    ("modicon", "plc"),
    ("melsec", "plc"),
    # --- Industrial Switches ---
    ("moxa", "industrial_switch"),
    ("hirschmann", "industrial_switch"),
    ("scalance", "industrial_switch"),
    # --- RTU ---
    ("scadapack", "rtu"),
    ("rtu-", "rtu"),
    # --- HMI ---
    ("panelview", "hmi"),
    ("magelis", "hmi"),
    ("ignition", "hmi"),
    # --- CNC ---
    ("sinumerik", "cnc_machine"),
    ("mazatrol", "cnc_machine"),
    ("fanuc-cnc", "cnc_machine"),
    # --- Industrial Robots ---
    ("fanuc-r", "industrial_robot"),
    ("kuka-kr", "industrial_robot"),
    ("ur5", "industrial_robot"),
    ("ur10", "industrial_robot"),
    ("ur3", "industrial_robot"),
    # --- Power Meters ---
    ("ion-", "power_meter"),
    ("sentron", "power_meter"),
    # --- Building Automation ---
    ("jace-", "building_automation"),
    ("tridium", "building_automation"),
    ("bacnet", "building_automation"),
    ("metasys", "building_automation"),
    ("niagara", "building_automation"),
    ("tracer", "building_automation"),
    # --- Access Control ---
    ("mercury-", "access_control"),
    ("synergis", "access_control"),
    # --- Fire Alarm ---
    ("notifier", "fire_alarm"),
    ("simplex", "fire_alarm"),
    ("cerberus", "fire_alarm"),
    ("vesda", "fire_alarm"),
    # --- Elevator ---
    ("otis-", "elevator_controller"),
    ("schindler", "elevator_controller"),
    ("kone-", "elevator_controller"),
    # --- Medical ---
    ("patient-monitor", "medical_device"),
    ("infusion-pump", "medical_device"),
    ("ventilator", "medical_device"),
    ("intellivue", "medical_device"),
    ("carescape", "medical_device"),
    ("alaris", "medical_device"),
    ("dicom", "medical_device"),
    ("benevision", "medical_device"),
    ("sigma-spectrum", "medical_device"),
    ("infusomat", "medical_device"),
    ("perfusor", "medical_device"),
    # --- Kiosk ---
    ("ncr-", "kiosk"),
    ("ssco-", "kiosk"),
    ("self-checkout", "kiosk"),
    # --- AV / Room Control ---
    ("crestron", "video_conferencing"),
    ("airmedia", "wireless_presentation"),
    ("control4", "smart_home"),
    # --- Digital Signage ---
    ("brightsign", "digital_signage"),
    ("magicinfo", "digital_signage"),
    # --- Label/Badge Printers ---
    ("dymo", "printer"),
    ("evolis", "printer"),
    ("ztc-", "printer"),
    # --- SBCs ---
    ("beaglebone", "sbc"),
    ("odroid", "sbc"),
    ("orangepi", "sbc"),
    ("bananapi", "sbc"),
    ("rock-", "sbc"),
    ("stellarmate", "sbc"),
    ("asiair", "sbc"),
    # --- Lab Instruments ---
    ("tek-", "lab_instrument"),
    ("rigol-", "lab_instrument"),
    ("siglent", "lab_instrument"),
    # --- Weather Stations ---
    ("weatherlink", "weather_station"),
    ("weatherbridge", "weather_station"),
    ("gw1000", "weather_station"),
    ("gw2000", "weather_station"),
    ("ecowitt", "weather_station"),
    ("tempest-hub", "weather_station"),
    # --- Interactive Displays ---
    ("smart-board", "interactive_display"),
    ("smartboard", "interactive_display"),
    ("activpanel", "interactive_display"),
    # --- AV Controllers ---
    ("extron", "video_conferencing"),
    ("amx-", "video_conferencing"),
    ("qsys", "video_conferencing"),
    # --- Telescope ---
    ("celestron", "lab_instrument"),
    ("synscan", "lab_instrument"),
    # --- Library Kiosk ---
    ("bibliotheca", "kiosk"),
]

# mDNS services that override device_type
_MDNS_SERVICE_TYPE_OVERRIDE: dict[str, str] = {
    "_airplay._tcp": "smart_speaker",  # AirPlay speakers
    "_raop._tcp": "smart_speaker",     # Remote Audio Output
    "_spotify-connect._tcp": "smart_speaker",
    "_sonos._tcp": "smart_speaker",
    "_googlecast._tcp": "smart_speaker",
    "_googlezone._tcp": "smart_speaker",
    "_googlehomedevice._tcp": "smart_speaker",
    "_amzn-wplay._tcp": "smart_speaker",
    "_home-assistant._tcp": "smart_home",
    "_hass._tcp": "smart_home",
    "_sftp-ssh._tcp": "server",
    "_smb._tcp": "server",
    "_nfs._tcp": "server",
    "_afpovertcp._tcp": "server",
    "_readynas._tcp": "nas",
    "_printer._tcp": "printer",
    "_ipp._tcp": "printer",
    "_ipps._tcp": "printer",
    "_scanner._tcp": "scanner",
    "_roku._tcp": "streaming_device",
    "_androidtvremote._tcp": "smart_tv",
    "_androidtvremote2._tcp": "smart_tv",
    "_samsungtv._tcp": "smart_tv",
    "_samsungtvrc._tcp": "smart_tv",
    "_lgtv._tcp": "smart_tv",
    "_lgtvremote._tcp": "smart_tv",
    "_viziocast._tcp": "smart_tv",
    "_clickshare._tcp": "wireless_presentation",
    "_mirrorop2upc._tcp": "wireless_presentation",
    "_crestron-cip._tcp": "video_conferencing",
    "_c4._tcp": "smart_home",
    "_dicom._tcp": "medical_device",
    "_lxi._tcp": "lab_instrument",
    "_vxi-11._tcp": "lab_instrument",
}


def _refine_type_from_context(
    device_type: str,
    hostname: str | None,
    mdns_services: list[str] | None,
) -> str:
    """Further refine device_type using hostname patterns and mDNS services.

    This runs AFTER vendor inference and handles cases where the hostname
    or observed services give a more specific classification.
    """
    # Don't override specific product types that were set by explicit normalization
    _SPECIFIC_TYPES = frozenset({
        "smart_display", "doorbell", "thermostat", "smart_lock",
        "smart_lighting", "smart_plug", "game_console",
    })
    if device_type in _SPECIFIC_TYPES:
        return device_type

    # Hostname patterns run FIRST — product names are more specific than mDNS
    # (e.g., "Google-Nest-Hub-Max" → smart_display, even though _googlecast → speaker)
    if hostname:
        hn_lower = hostname.lower()
        for pattern, inferred_type in _HOSTNAME_DEVICE_HINTS:
            if pattern in hn_lower:
                if pattern == "switch" and device_type in ("switch", "router", "access_point"):
                    continue
                return inferred_type

    # mDNS services — strong signal for generic types
    if mdns_services:
        # Count votes per type from services
        type_votes: dict[str, int] = {}
        for svc in mdns_services:
            override = _MDNS_SERVICE_TYPE_OVERRIDE.get(svc)
            if override:
                type_votes[override] = type_votes.get(override, 0) + 1

        if type_votes:
            best_type = max(type_votes, key=type_votes.get)
            vote_count = type_votes[best_type]
            # Don't let mDNS reclassify PCs/workstations — Chrome casts _googlecast
            # but the device is still a workstation, not a speaker
            if device_type in ("workstation", "computer", "server", "nas"):
                # Only override a PC if there are 3+ non-cast services voting
                non_cast_votes = sum(v for k, v in type_votes.items() if k != "smart_speaker")
                if non_cast_votes >= 2:
                    return max((k for k in type_votes if k != "smart_speaker"), key=type_votes.get)
                return device_type
            # For generic/IoT types, mDNS is strong signal
            if vote_count >= 2 or device_type in ("unknown", "iot", "smart_home", "mobile"):
                return best_type

    return device_type


def _subnet_for_ip(ip: str | None) -> str | None:
    if not ip:
        return None
    try:
        net = ipaddress.ip_network(f"{ip}/24", strict=False)
        return str(net)
    except (ValueError, TypeError):
        return None


def _clean_hostname(hostname: str | None, device_type: str,
                     manufacturer: str | None = None,
                     model: str | None = None) -> str | None:
    if not hostname:
        # For Ubiquiti network_devices with no hostname, show model or a
        # disambiguating label so they don't all appear identical.
        if device_type == "network_device" and manufacturer and "ubiquiti" in manufacturer.lower():
            if model:
                return model
            return "Ubiquiti (AP/SW?)"
        return None
    hn = hostname.strip()
    if hn.count(".") >= 2 and not hn.endswith(".local"):
        return None
    if len(hn) > 50:
        return None
    return hn


def build_topology_graph(
    *,
    devices: list[dict],
    gateways: list[dict],
    arp_entries: list[dict],
    lldp_neighbors: list[dict],
    device_mdns_services: dict[str, list[str]] | None = None,
    overrides: dict[str, str] | None = None,
) -> dict:
    gateway_macs = {g["mac"] for g in gateways}
    device_by_mac: dict[str, dict] = {}
    subnets: set[str] = set()

    gateway_subnet_to_mac: dict[str, str] = {}
    gateway_subnets: dict[str, str] = {}
    for gw in gateways:
        s = _subnet_for_ip(gw["ip"])
        if s:
            gateway_subnet_to_mac[s] = gw["mac"]
            gateway_subnets[s] = gw["mac"]

    # --- Validate gateways ---
    device_type_by_mac = {d["mac"]: _infer_type_from_vendor(_normalize_device_type(d.get("device_type")), d.get("manufacturer")) for d in devices}
    bad_gateways = set()
    for gw_mac in gateway_macs:
        gw_type = device_type_by_mac.get(gw_mac, "unknown")
        if gw_type not in _INFRA_TYPES:
            bad_gateways.add(gw_mac)

    if bad_gateways and any(dt in _INFRA_TYPES for dt in device_type_by_mac.values()):
        gateway_macs -= bad_gateways
        gateways = [g for g in gateways if g["mac"] not in bad_gateways]
        for d in devices:
            dt = _normalize_device_type(d.get("device_type"))
            if dt == "router" and d["mac"] not in gateway_macs and d.get("ip_v4"):
                gateways.append({"mac": d["mac"], "ip": d["ip_v4"], "source": "inferred"})
                gateway_macs.add(d["mac"])
        gateway_subnet_to_mac.clear()
        gateway_subnets.clear()
        for gw in gateways:
            s = _subnet_for_ip(gw["ip"])
            if s:
                gateway_subnet_to_mac[s] = gw["mac"]
                gateway_subnets[s] = gw["mac"]

    # --- Build device nodes ---
    device_nodes = []
    for d in devices:
        mac = d["mac"]
        # Skip devices with no IP at all — they have no network presence to map
        # (e.g., monitoring interfaces that only see LLDP)
        if not d.get("ip_v4") and not d.get("ip_v6"):
            continue
        device_type = _normalize_device_type(d.get("device_type"))
        device_type = _infer_type_from_vendor(device_type, d.get("manufacturer"))
        mdns_svcs = (device_mdns_services or {}).get(mac)
        device_type = _refine_type_from_context(device_type, d.get("hostname"), mdns_svcs)

        # Refine "network_device" using LLDP presence and model/hostname hints
        if device_type == "network_device":
            model = (d.get("model") or d.get("hostname") or "").lower()
            has_lldp = mac in {n.get("device_mac") for n in lldp_neighbors}
            has_lldp_chassis = mac in {n.get("neighbor_mac") for n in lldp_neighbors}
            has_cdp = mac in {n.get("device_mac") for n in lldp_neighbors if n.get("port_id")}
            # Check for AP indicators in model/hostname
            ap_keywords = ("uap", "u6", "u7", "ap ", "access point", "nanostation",
                           "litebeam", "nanobeam", "powerbeam", "unifi ap", "ac-lite",
                           "ac-lr", "ac-pro", "ac-hd", "ac-mesh", "flexhd", "in-wall",
                           "basestation", "-ap-", "eap", "wap", "aruba ap", "ruckus")
            switch_keywords = ("usw", "switch", "us-", "us8", "us16", "us24", "us48",
                               "unifi switch", "catalyst", "prosafe", "gs1", "gs3")
            router_keywords = ("udm", "ucg", "udr", "usg", "edgerouter",
                               "dream machine", "cloud gateway", "security gateway")
            if any(kw in model for kw in ap_keywords):
                device_type = "access_point"
            elif any(kw in model for kw in switch_keywords):
                device_type = "switch"
            elif any(kw in model for kw in router_keywords):
                device_type = "router"
            elif has_lldp or has_lldp_chassis:
                # LLDP-capable network_device — check if on same subnet as known APs
                dev_subnet = _subnet_for_ip(d.get("ip_v4"))
                ap_subnets = set()
                for other in devices:
                    otype = _normalize_device_type(other.get("device_type"))
                    osub = _subnet_for_ip(other.get("ip_v4"))
                    if otype == "access_point" and osub:
                        ap_subnets.add(osub)
                if dev_subnet and dev_subnet in ap_subnets:
                    device_type = "access_point"
            else:
                # Ubiquiti network_device with NO LLDP: likely an AP.
                # Switches always send LLDP; APs often don't on monitored VLANs.
                mfr = (d.get("manufacturer") or "").lower()
                if mfr in ("ubiquiti", "ubiquiti inc", "ubiquiti networks"):
                    device_type = "access_point"

        is_gw = mac in gateway_macs
        is_infra = device_type in _INFRA_TYPES and not is_gw
        subnet = _subnet_for_ip(d.get("ip_v4"))
        if subnet:
            subnets.add(subnet)

        # Online/offline
        last_seen = d.get("last_seen")
        is_online = False
        if last_seen:
            try:
                from datetime import datetime, timedelta, timezone
                ls = datetime.fromisoformat(last_seen) if isinstance(last_seen, str) else last_seen
                now = datetime.now(timezone.utc)
                # Handle both naive and aware datetimes from DB
                if ls.tzinfo is None:
                    ls = ls.replace(tzinfo=timezone.utc)
                is_online = (now - ls) < timedelta(minutes=30)
            except Exception:
                pass

        node = {
            "id": mac,
            "type": device_type,
            "hostname": _clean_hostname(d.get("hostname"), device_type,
                                        d.get("manufacturer"), d.get("model")),
            "ip": d.get("ip_v4") or d.get("ip_v6"),
            "model": d.get("model"),
            "manufacturer": d.get("manufacturer"),
            "confidence": d.get("confidence", 0),
            "subnet": subnet,
            "is_gateway": is_gw,
            "is_infrastructure": is_infra,
            "is_online": is_online,
            "last_seen": d.get("last_seen"),
            "os_family": d.get("os_family"),
            "connection_type": d.get("connection_type", "unknown"),
            "is_self": d.get("alert_status") == "self",
            "all_ips": d.get("all_ips"),
        }
        device_nodes.append(node)
        device_by_mac[mac] = node

    # --- Build LLDP neighbor maps ---
    lldp_links: dict[str, set[str]] = {}  # bidirectional
    lldp_port_info: dict[tuple[str, str], str] = {}
    for n in lldp_neighbors:
        src = n.get("device_mac")
        dst = n.get("neighbor_mac")
        if src and dst:
            lldp_links.setdefault(src, set()).add(dst)
            lldp_links.setdefault(dst, set()).add(src)
            if n.get("port_id"):
                lldp_port_info[(src, dst)] = n["port_id"]

    # --- Identify the core switch ---
    # The core switch is the non-gateway infra device with the most ARP traffic
    # (it's the central point all traffic passes through)
    arp_by_mac: dict[str, int] = {}
    for e in arp_entries:
        m = e.get("mac")
        if m:
            arp_by_mac[m] = arp_by_mac.get(m, 0) + e.get("packet_count", 0)

    # Core switch = actual switch with the most ARP traffic
    switch_nodes = [n for n in device_nodes if n["is_infrastructure"]
                    and n["type"] in ("switch", "unifi switch") and not n["is_gateway"]]
    core_switch_mac = None
    if switch_nodes:
        switch_by_arp = sorted(switch_nodes, key=lambda n: arp_by_mac.get(n["id"], 0), reverse=True)
        core_switch_mac = switch_by_arp[0]["id"]

    # --- Categorize infrastructure ---
    switches = [n for n in device_nodes if n["is_infrastructure"]
                and n["type"] in ("switch", "unifi switch") and not n["is_gateway"]]
    aps = [n for n in device_nodes if n["is_infrastructure"] and n["type"] == "access_point"]

    # --- Build output nodes (no subnet group nodes — devices connect directly) ---
    nodes = []

    # Internet cloud node at the very top
    nodes.append({
        "id": "internet",
        "type": "internet",
        "hostname": None,
        "ip": None,
        "manufacturer": None,
        "confidence": 100,
        "subnet": None,
        "is_gateway": False,
        "is_infrastructure": False,
        "is_online": True,
        "last_seen": None,
        "os_family": None,
        "connection_type": "wired",
        "tier": "internet",
        "parent_group": None,
    })

    # Gateway nodes
    for n in device_nodes:
        if n["is_gateway"]:
            nodes.append({**n, "tier": "gateway", "parent_group": None})

    # Infrastructure nodes
    # When no gateway exists, promote the core switch to gateway tier
    # so it sits at the top of the hierarchy
    promote_core = not gateways and core_switch_mac
    for n in device_nodes:
        if not n["is_infrastructure"] or n["is_gateway"]:
            continue
        is_core = n["id"] == core_switch_mac
        tier = "gateway" if (promote_core and is_core) else "infrastructure"
        nodes.append({**n, "tier": tier, "parent_group": None, "is_core_switch": is_core})

    # Client nodes
    for n in device_nodes:
        if n["is_gateway"] or n["is_infrastructure"]:
            continue
        nodes.append({**n, "tier": "client", "parent_group": None})

    # --- Build edges ---
    edges = []
    connected: set[tuple[str, str]] = set()

    # 0. Internet → Gateway (or core switch if no gateway)
    if gateways:
        for gw in gateways:
            edges.append({
                "source": "internet",
                "target": gw["mac"],
                "type": "wan_link",
            })
    elif core_switch_mac:
        # No gateway found — connect internet directly to core switch
        edges.append({
            "source": "internet",
            "target": core_switch_mac,
            "type": "wan_link",
        })

    # 1. Gateway → Core Switch (direct connection)
    if core_switch_mac:
        for gw in gateways:
            pair = tuple(sorted([gw["mac"], core_switch_mac]))
            if pair not in connected:
                connected.add(pair)
                edges.append({
                    "source": gw["mac"],
                    "target": core_switch_mac,
                    "type": "trunk_link",
                })

    # 2. Core Switch → other switches/APs
    if core_switch_mac:
        for n in device_nodes:
            if not n["is_infrastructure"] or n["is_gateway"] or n["id"] == core_switch_mac:
                continue
            pair = tuple(sorted([core_switch_mac, n["id"]]))
            if pair not in connected:
                connected.add(pair)
                port = lldp_port_info.get((core_switch_mac, n["id"])) or lldp_port_info.get((n["id"], core_switch_mac))
                edges.append({
                    "source": core_switch_mac,
                    "target": n["id"],
                    "type": "trunk_link",
                    "port_id": port,
                })

    # 3. LLDP/CDP known links (add any not already covered)
    for nb in lldp_neighbors:
        src = nb.get("device_mac")
        dst = nb.get("neighbor_mac")
        if src and dst and src in device_by_mac and dst in device_by_mac:
            pair = tuple(sorted([src, dst]))
            if pair not in connected:
                connected.add(pair)
                edges.append({
                    "source": src,
                    "target": dst,
                    "type": "lldp",
                    "port_id": nb.get("port_id"),
                })

    # 4. (Subnet group nodes removed — no vlan_link edges needed)

    # 5. Client → infrastructure edges
    #
    # Wireless clients: distribute across APs (subnet affinity, then round-robin).
    # Wired clients: distribute across all switches (not just core switch).
    # This produces a more realistic topology when LLDP data is unavailable.
    ap_by_subnet: dict[str, list[str]] = {}
    for ap in aps:
        ap_sub = ap.get("subnet")
        if ap_sub:
            ap_by_subnet.setdefault(ap_sub, []).append(ap["id"])
    ap_round_robin_idx = 0

    # Build list of all switches (including core) for wired client distribution
    all_switches = [n["id"] for n in device_nodes
                    if n["is_infrastructure"] and n["type"] in ("switch", "unifi switch") and not n["is_gateway"]]

    # Detect VM-to-host relationships for bridged VMs.
    # VM MACs (VMware 00:0C:29/00:50:56, QEMU 52:54:00, etc.) on the same
    # subnet as a physical host suggest a bridge — link VM to host.
    _VM_OUI_PREFIXES = {"00:0c:29", "00:50:56", "52:54:00", "00:16:3e", "08:00:27"}
    vm_to_host: dict[str, str] = {}
    for n in device_nodes:
        mac_prefix = n["id"][:8].lower()
        if mac_prefix not in _VM_OUI_PREFIXES:
            continue
        vm_subnet = n.get("subnet")
        if not vm_subnet:
            continue
        # Find a non-VM, non-infra host on the same subnet that could be the hypervisor
        for candidate in device_nodes:
            if candidate["id"] == n["id"]:
                continue
            if candidate["is_gateway"] or candidate["is_infrastructure"]:
                continue
            if candidate.get("subnet") != vm_subnet:
                continue
            cand_prefix = candidate["id"][:8].lower()
            if cand_prefix in _VM_OUI_PREFIXES:
                continue
            # Prefer workstations/computers as VM hosts
            cand_type = candidate.get("type", "")
            if cand_type in ("workstation", "computer", "server", "desktop", "laptop"):
                vm_to_host[n["id"]] = candidate["id"]
                break

    for n in device_nodes:
        if n["is_gateway"] or n["is_infrastructure"]:
            continue
        subnet = n.get("subnet")
        mac = n["id"]
        conn_type = n.get("connection_type", "unknown")
        dt = (n.get("type") or "").lower()

        # Self device (leetha host) — always connect to a switch on the same subnet
        if n.get("is_self") and all_switches:
            same_subnet_switches = [sw for sw in all_switches if device_by_mac.get(sw, {}).get("subnet") == subnet]
            target_switch = same_subnet_switches[0] if same_subnet_switches else all_switches[0]
            pair = tuple(sorted([target_switch, mac]))
            if pair not in connected:
                connected.add(pair)
                edges.append({"source": target_switch, "target": mac, "type": "client_link"})
            continue

        # LLDP-known link — always preferred
        lldp_parent = None
        if mac in lldp_links:
            for neighbor in lldp_links[mac]:
                nb = device_by_mac.get(neighbor)
                if nb and nb.get("is_infrastructure"):
                    lldp_parent = neighbor
                    break

        if lldp_parent:
            pair = tuple(sorted([mac, lldp_parent]))
            if pair not in connected:
                connected.add(pair)
                edges.append({"source": lldp_parent, "target": mac, "type": "client_link"})
        elif mac in vm_to_host:
            # Bridged VM → connect to its hypervisor host
            host_mac = vm_to_host[mac]
            edges.append({"source": host_mac, "target": mac, "type": "vm_link"})
        elif conn_type == "wireless" or (conn_type == "unknown" and aps and not all_switches):
            # Wireless → connect through an AP
            # Unknown with APs but no switches → assume wireless (home networks)
            ap_target = None
            if subnet and subnet in ap_by_subnet:
                subnet_aps = ap_by_subnet[subnet]
                ap_target = subnet_aps[hash(mac) % len(subnet_aps)]
            elif aps:
                ap_target = aps[ap_round_robin_idx % len(aps)]["id"]
                ap_round_robin_idx += 1

            if ap_target:
                edges.append({"source": ap_target, "target": mac, "type": "wireless_link"})
            elif core_switch_mac:
                edges.append({"source": core_switch_mac, "target": mac, "type": "wireless_link"})
            else:
                # No APs or core switch — fall back to gateway
                gw = gateway_subnet_to_mac.get(subnet) or next(iter(gateway_macs), None)
                if gw:
                    edges.append({"source": gw, "target": mac, "type": "wireless_link"})
                else:
                    edges.append({"source": "internet", "target": mac, "type": "client_link"})
        elif conn_type == "unknown" and aps:
            # Unknown with both APs and switches — route through AP if device
            # type suggests a client device (not infrastructure)
            is_client = dt not in _INFRA_TYPES if dt else True
            if is_client:
                ap_target = None
                if subnet and subnet in ap_by_subnet:
                    subnet_aps = ap_by_subnet[subnet]
                    ap_target = subnet_aps[hash(mac) % len(subnet_aps)]
                elif aps:
                    ap_target = aps[ap_round_robin_idx % len(aps)]["id"]
                    ap_round_robin_idx += 1
                if ap_target:
                    edges.append({"source": ap_target, "target": mac, "type": "wireless_link"})
                elif core_switch_mac:
                    edges.append({"source": core_switch_mac, "target": mac, "type": "client_link"})
                else:
                    gw = gateway_subnet_to_mac.get(subnet) or next(iter(gateway_macs), None)
                    if gw:
                        edges.append({"source": gw, "target": mac, "type": "client_link"})
            elif all_switches:
                target_switch = all_switches[hash(mac) % len(all_switches)]
                edges.append({"source": target_switch, "target": mac, "type": "client_link"})
            elif core_switch_mac:
                edges.append({"source": core_switch_mac, "target": mac, "type": "client_link"})
            else:
                gw = gateway_subnet_to_mac.get(subnet) or next(iter(gateway_macs), None)
                if gw:
                    edges.append({"source": gw, "target": mac, "type": "client_link"})
        elif all_switches and conn_type == "wired":
            # Definitively wired → distribute across switches
            target_switch = all_switches[hash(mac) % len(all_switches)]
            edges.append({"source": target_switch, "target": mac, "type": "client_link"})
        elif core_switch_mac:
            edges.append({"source": core_switch_mac, "target": mac, "type": "client_link"})
        else:
            gw = gateway_subnet_to_mac.get(subnet) or next(iter(gateway_macs), None)
            if gw:
                edges.append({"source": gw, "target": mac, "type": "client_link"})
            else:
                # Last resort: connect to any infrastructure node or internet
                any_infra = next((n["id"] for n in device_nodes if n["is_infrastructure"] or n["is_gateway"]), None)
                edges.append({"source": any_infra or "internet", "target": mac, "type": "client_link"})

    # --- Apply manual topology overrides ---
    if overrides:
        for child_mac, parent_mac in overrides.items():
            # Only apply if both devices exist in the graph
            if child_mac not in device_by_mac:
                continue
            if parent_mac != "internet" and parent_mac not in device_by_mac:
                continue

            # Remove all auto-generated edges where this device is the TARGET
            edges = [e for e in edges if e["target"] != child_mac]

            # Add the manual edge
            edges.append({
                "source": parent_mac,
                "target": child_mac,
                "type": "manual_link",
            })

    return {
        "nodes": nodes,
        "edges": edges,
        "subnets": sorted(subnets),
    }
