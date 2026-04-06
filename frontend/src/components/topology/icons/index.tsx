import { type SVGProps } from "react";

type IconProps = SVGProps<SVGSVGElement> & { size?: number };

function SvgBase({ size = 40, children, ...props }: IconProps & { children: React.ReactNode }) {
  return (
    <svg width={size} height={size} viewBox="0 0 40 40" fill="none" stroke="currentColor"
      strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" {...props}>
      {children}
    </svg>
  );
}

export function IconRouter(props: IconProps) {
  return (
    <SvgBase {...props}>
      <rect x="6" y="18" width="28" height="14" rx="2" />
      <line x1="12" y1="25" x2="14" y2="25" strokeWidth="2" />
      <line x1="17" y1="25" x2="19" y2="25" strokeWidth="2" />
      <circle cx="30" cy="25" r="1.5" fill="currentColor" />
      <line x1="13" y1="18" x2="10" y2="8" />
      <line x1="27" y1="18" x2="30" y2="8" />
      <circle cx="10" cy="7" r="1.5" />
      <circle cx="30" cy="7" r="1.5" />
    </SvgBase>
  );
}

export function IconSwitch(props: IconProps) {
  return (
    <SvgBase {...props}>
      <rect x="4" y="14" width="32" height="12" rx="2" />
      <line x1="10" y1="18" x2="10" y2="22" />
      <line x1="14" y1="18" x2="14" y2="22" />
      <line x1="18" y1="18" x2="18" y2="22" />
      <line x1="22" y1="18" x2="22" y2="22" />
      <line x1="26" y1="18" x2="26" y2="22" />
      <line x1="30" y1="18" x2="30" y2="22" />
      <circle cx="8" cy="20" r="1" fill="currentColor" />
    </SvgBase>
  );
}

export function IconAccessPoint(props: IconProps) {
  return (
    <SvgBase {...props}>
      <ellipse cx="20" cy="28" rx="10" ry="4" />
      <path d="M10 28 Q10 20 20 16 Q30 20 30 28" />
      <path d="M14 13 Q20 8 26 13" />
      <path d="M11 10 Q20 3 29 10" />
    </SvgBase>
  );
}

export function IconFirewall(props: IconProps) {
  return (
    <SvgBase {...props}>
      <path d="M20 4 L34 10 L34 22 Q34 32 20 37 Q6 32 6 22 L6 10 Z" />
      <line x1="6" y1="16" x2="34" y2="16" />
      <line x1="6" y1="24" x2="34" y2="24" />
      <line x1="20" y1="10" x2="20" y2="16" />
      <line x1="13" y1="16" x2="13" y2="24" />
      <line x1="27" y1="16" x2="27" y2="24" />
      <line x1="20" y1="24" x2="20" y2="30" />
    </SvgBase>
  );
}

export function IconServer(props: IconProps) {
  return (
    <SvgBase {...props}>
      <rect x="8" y="4" width="24" height="10" rx="1" />
      <rect x="8" y="16" width="24" height="10" rx="1" />
      <rect x="8" y="28" width="24" height="8" rx="1" />
      <circle cx="28" cy="9" r="1.5" fill="currentColor" />
      <circle cx="28" cy="21" r="1.5" fill="currentColor" />
      <circle cx="28" cy="32" r="1.5" fill="currentColor" />
      <line x1="12" y1="9" x2="18" y2="9" />
      <line x1="12" y1="21" x2="18" y2="21" />
    </SvgBase>
  );
}

export function IconWorkstation(props: IconProps) {
  return (
    <SvgBase {...props}>
      <rect x="6" y="4" width="28" height="20" rx="2" />
      <rect x="10" y="7" width="20" height="14" rx="1" fill="currentColor" fillOpacity="0.1" />
      <line x1="16" y1="24" x2="16" y2="30" />
      <line x1="24" y1="24" x2="24" y2="30" />
      <line x1="12" y1="30" x2="28" y2="30" />
    </SvgBase>
  );
}

export function IconLaptop(props: IconProps) {
  return (
    <SvgBase {...props}>
      <rect x="8" y="6" width="24" height="18" rx="2" />
      <rect x="10" y="8" width="20" height="13" rx="1" fill="currentColor" fillOpacity="0.1" />
      <path d="M4 28 L8 24 L32 24 L36 28 Z" />
    </SvgBase>
  );
}

export function IconSmartphone(props: IconProps) {
  return (
    <SvgBase {...props}>
      <rect x="12" y="4" width="16" height="32" rx="3" />
      <line x1="18" y1="7" x2="22" y2="7" />
      <circle cx="20" cy="32" r="1.5" />
      <rect x="14" y="10" width="12" height="18" rx="1" fill="currentColor" fillOpacity="0.1" />
    </SvgBase>
  );
}

export function IconTablet(props: IconProps) {
  return (
    <SvgBase {...props}>
      <rect x="8" y="4" width="24" height="32" rx="3" />
      <circle cx="20" cy="32" r="1.5" />
      <rect x="10" y="7" width="20" height="22" rx="1" fill="currentColor" fillOpacity="0.1" />
    </SvgBase>
  );
}

export function IconSmartTV(props: IconProps) {
  return (
    <SvgBase {...props}>
      <rect x="4" y="6" width="32" height="20" rx="1" />
      <rect x="6" y="8" width="28" height="16" rx="1" fill="currentColor" fillOpacity="0.1" />
      <line x1="14" y1="26" x2="14" y2="32" />
      <line x1="26" y1="26" x2="26" y2="32" />
      <line x1="10" y1="32" x2="30" y2="32" />
    </SvgBase>
  );
}

export function IconSmartSpeaker(props: IconProps) {
  return (
    <SvgBase {...props}>
      <ellipse cx="20" cy="32" rx="10" ry="3" />
      <path d="M10 32 L10 18 Q10 6 20 6 Q30 6 30 18 L30 32" />
      <circle cx="20" cy="18" r="4" fill="currentColor" fillOpacity="0.15" />
      <circle cx="20" cy="18" r="1.5" fill="currentColor" fillOpacity="0.3" />
    </SvgBase>
  );
}

export function IconPrinter(props: IconProps) {
  return (
    <SvgBase {...props}>
      <rect x="10" y="4" width="20" height="10" rx="1" />
      <rect x="6" y="14" width="28" height="14" rx="2" />
      <rect x="10" y="28" width="20" height="8" rx="1" />
      <circle cx="28" cy="18" r="1.5" fill="currentColor" />
    </SvgBase>
  );
}

export function IconCamera(props: IconProps) {
  return (
    <SvgBase {...props}>
      <circle cx="24" cy="20" r="6" />
      <circle cx="24" cy="20" r="3" fill="currentColor" fillOpacity="0.2" />
      <rect x="4" y="14" width="14" height="12" rx="2" />
      <line x1="10" y1="14" x2="10" y2="8" />
      <rect x="8" y="6" width="4" height="4" rx="1" />
    </SvgBase>
  );
}

export function IconNAS(props: IconProps) {
  return (
    <SvgBase {...props}>
      <rect x="8" y="4" width="24" height="32" rx="2" />
      <rect x="11" y="8" width="18" height="8" rx="1" />
      <rect x="11" y="19" width="18" height="8" rx="1" />
      <line x1="20" y1="30" x2="20" y2="33" strokeWidth="2" />
    </SvgBase>
  );
}

export function IconIoT(props: IconProps) {
  return (
    <SvgBase {...props}>
      <rect x="10" y="10" width="20" height="20" rx="2" />
      <circle cx="20" cy="20" r="4" fill="currentColor" fillOpacity="0.15" />
      <line x1="10" y1="16" x2="6" y2="16" />
      <line x1="10" y1="24" x2="6" y2="24" />
      <line x1="30" y1="16" x2="34" y2="16" />
      <line x1="30" y1="24" x2="34" y2="24" />
      <line x1="16" y1="10" x2="16" y2="6" />
      <line x1="24" y1="10" x2="24" y2="6" />
      <line x1="16" y1="30" x2="16" y2="34" />
      <line x1="24" y1="30" x2="24" y2="34" />
    </SvgBase>
  );
}

export function IconSmartHome(props: IconProps) {
  return (
    <SvgBase {...props}>
      <path d="M6 20 L20 8 L34 20" />
      <rect x="10" y="20" width="20" height="14" rx="1" />
      <rect x="16" y="26" width="8" height="8" />
      <path d="M26 14 Q30 10 34 14" />
      <path d="M28 11 Q32 6 36 11" />
    </SvgBase>
  );
}

export function IconGameConsole(props: IconProps) {
  return (
    <SvgBase {...props}>
      <path d="M8 16 Q4 16 4 22 Q4 28 8 28 L14 28 L16 24 L24 24 L26 28 L32 28 Q36 28 36 22 Q36 16 32 16 Z" />
      <circle cx="12" cy="21" r="2" />
      <circle cx="28" cy="21" r="1" fill="currentColor" />
      <circle cx="31" cy="18" r="1" fill="currentColor" />
    </SvgBase>
  );
}

export function IconStreamingDevice(props: IconProps) {
  return (
    <SvgBase {...props}>
      <ellipse cx="20" cy="24" rx="12" ry="6" />
      <ellipse cx="20" cy="22" rx="12" ry="6" fill="currentColor" fillOpacity="0.1" />
      <circle cx="20" cy="22" r="3" />
    </SvgBase>
  );
}

export function IconThermostat(props: IconProps) {
  return (
    <SvgBase {...props}>
      {/* Round thermostat */}
      <circle cx="20" cy="20" r="14" />
      <circle cx="20" cy="20" r="11" fill="currentColor" fillOpacity="0.08" />
      <path d="M20 12 L20 20" strokeWidth="2" />
      <path d="M20 20 L26 16" strokeWidth="1.5" />
      <circle cx="20" cy="20" r="2" fill="currentColor" />
      <path d="M13 28 L15 26" />
      <path d="M25 26 L27 28" />
    </SvgBase>
  );
}

export function IconDoorbell(props: IconProps) {
  return (
    <SvgBase {...props}>
      {/* Doorbell camera */}
      <rect x="12" y="4" width="16" height="32" rx="8" />
      <circle cx="20" cy="16" r="5" />
      <circle cx="20" cy="16" r="2.5" fill="currentColor" fillOpacity="0.2" />
      <circle cx="20" cy="28" r="2.5" fill="currentColor" fillOpacity="0.15" />
    </SvgBase>
  );
}

export function IconSmartLight(props: IconProps) {
  return (
    <SvgBase {...props}>
      {/* Light bulb */}
      <path d="M15 24 Q10 18 10 14 Q10 6 20 6 Q30 6 30 14 Q30 18 25 24 Z" />
      <rect x="15" y="24" width="10" height="4" rx="1" />
      <rect x="16" y="28" width="8" height="3" rx="1" />
      <line x1="16" y1="32" x2="24" y2="32" />
      <path d="M17 14 Q20 10 23 14" fill="none" strokeWidth="1" opacity="0.4" />
    </SvgBase>
  );
}

export function IconSmartPlug(props: IconProps) {
  return (
    <SvgBase {...props}>
      {/* Power plug */}
      <rect x="8" y="10" width="24" height="20" rx="4" />
      <rect x="12" y="14" width="16" height="12" rx="2" fill="currentColor" fillOpacity="0.08" />
      <circle cx="16" cy="20" r="2" />
      <circle cx="24" cy="20" r="2" />
      <line x1="20" y1="30" x2="20" y2="36" strokeWidth="2" />
    </SvgBase>
  );
}

export function IconSmartLock(props: IconProps) {
  return (
    <SvgBase {...props}>
      {/* Padlock */}
      <rect x="8" y="18" width="24" height="16" rx="3" />
      <path d="M13 18 L13 12 Q13 4 20 4 Q27 4 27 12 L27 18" fill="none" />
      <circle cx="20" cy="26" r="3" fill="currentColor" fillOpacity="0.2" />
      <line x1="20" y1="27" x2="20" y2="30" strokeWidth="2" />
    </SvgBase>
  );
}

export function IconSmartDisplay(props: IconProps) {
  return (
    <SvgBase {...props}>
      {/* Tablet-like display on stand with speaker dots */}
      <rect x="6" y="6" width="28" height="20" rx="2" />
      <rect x="8" y="8" width="24" height="16" rx="1" fill="currentColor" fillOpacity="0.1" />
      <line x1="20" y1="26" x2="20" y2="30" />
      <line x1="14" y1="30" x2="26" y2="30" />
      <circle cx="20" cy="33" r="1" fill="currentColor" fillOpacity="0.3" />
      <circle cx="24" cy="33" r="1" fill="currentColor" fillOpacity="0.3" />
      <circle cx="16" cy="33" r="1" fill="currentColor" fillOpacity="0.3" />
    </SvgBase>
  );
}

export function IconWearable(props: IconProps) {
  return (
    <SvgBase {...props}>
      {/* Watch/wearable */}
      <rect x="12" y="6" width="16" height="6" rx="2" />
      <rect x="10" y="12" width="20" height="16" rx="4" />
      <rect x="12" y="28" width="16" height="6" rx="2" />
      <circle cx="20" cy="20" r="5" fill="currentColor" fillOpacity="0.1" />
      <line x1="20" y1="17" x2="20" y2="20" strokeWidth="1.5" />
      <line x1="20" y1="20" x2="23" y2="22" strokeWidth="1.5" />
    </SvgBase>
  );
}

export function IconVoipPhone(props: IconProps) {
  return (
    <SvgBase {...props}>
      {/* Desk phone with handset */}
      <rect x="8" y="14" width="24" height="18" rx="2" />
      <rect x="11" y="17" width="10" height="6" rx="1" fill="currentColor" fillOpacity="0.1" />
      <circle cx="26" cy="20" r="1.5" />
      <circle cx="26" cy="25" r="1.5" />
      <circle cx="22" cy="25" r="1.5" />
      <path d="M10 14 Q8 8 12 6 L28 6 Q32 8 30 14" />
    </SvgBase>
  );
}

export function IconMeshRouter(props: IconProps) {
  return (
    <SvgBase {...props}>
      {/* Mesh router puck with signal */}
      <ellipse cx="20" cy="28" rx="12" ry="5" />
      <path d="M8 28 L8 22 Q8 16 20 16 Q32 16 32 22 L32 28" />
      <path d="M14 13 Q20 8 26 13" />
      <path d="M11 10 Q20 3 29 10" />
    </SvgBase>
  );
}

export function IconInternet(props: IconProps) {
  return (
    <SvgBase {...props}>
      {/* Cloud / Globe */}
      <circle cx="20" cy="20" r="12" />
      <ellipse cx="20" cy="20" rx="12" ry="5" />
      <path d="M14 12 Q14 20 14 28" />
      <path d="M26 12 Q26 20 26 28" />
      <line x1="8" y1="20" x2="32" y2="20" />
    </SvgBase>
  );
}

export function IconUnknown(props: IconProps) {
  return (
    <SvgBase {...props}>
      {/* Generic device — monitor with signal */}
      <rect x="8" y="8" width="24" height="16" rx="2" />
      <rect x="10" y="10" width="20" height="12" rx="1" fill="currentColor" fillOpacity="0.08" />
      <line x1="16" y1="24" x2="16" y2="28" />
      <line x1="24" y1="24" x2="24" y2="28" />
      <line x1="12" y1="28" x2="28" y2="28" />
      <path d="M26 13 Q29 10 32 13" fill="none" strokeWidth="1" opacity="0.4" />
      <path d="M28 11 Q31 8 34 11" fill="none" strokeWidth="1" opacity="0.3" />
    </SvgBase>
  );
}

export const DEVICE_ICON_MAP: Record<string, React.ComponentType<IconProps>> = {
  // Infrastructure
  internet: IconInternet,
  router: IconRouter,
  gateway: IconRouter,
  switch: IconSwitch,
  access_point: IconAccessPoint,
  mesh_router: IconAccessPoint,
  firewall: IconFirewall,
  load_balancer: IconServer,
  // Compute
  server: IconServer,
  hypervisor: IconServer,
  container_host: IconServer,
  kubernetes_node: IconServer,
  container: IconServer,
  kvm_host: IconServer,
  hyper_v: IconServer,
  ai_gateway: IconServer,
  // Desktop
  workstation: IconWorkstation,
  desktop: IconWorkstation,
  laptop: IconLaptop,
  computer: IconLaptop,
  // Mobile
  smartphone: IconSmartphone,
  phone: IconSmartphone,
  mobile: IconSmartphone,
  tablet: IconTablet,
  // Entertainment
  smart_tv: IconSmartTV,
  smart_speaker: IconSmartSpeaker,
  smart_display: IconSmartDisplay,
  media_player: IconStreamingDevice,
  streaming_device: IconStreamingDevice,
  game_console: IconGameConsole,
  // Office
  printer: IconPrinter,
  scanner: IconPrinter,
  // Security / Cameras
  camera: IconCamera,
  ip_camera: IconCamera,
  // Storage
  nas: IconNAS,
  // IoT / Smart Home
  iot: IconIoT,
  smart_home: IconSmartHome,
  thermostat: IconThermostat,
  doorbell: IconDoorbell,
  smart_lighting: IconSmartLight,
  smart_plug: IconSmartPlug,
  smart_lock: IconSmartLock,
  embedded: IconIoT,
  wearable: IconWearable,
  mesh_router: IconMeshRouter,
  voip_phone: IconVoipPhone,
  // Appliances / Home
  appliance: IconSmartHome,
  smoke_detector: IconSmartHome,
  garage_door: IconSmartHome,
  irrigation: IconIoT,
  air_purifier: IconIoT,
  baby_monitor: IconCamera,
  pet_device: IconCamera,
  // Entertainment / AV
  projector: IconSmartTV,
  media_server: IconServer,
  digital_signage: IconSmartTV,
  video_conferencing: IconSmartDisplay,
  // Industrial / Enterprise
  "3d_printer": IconPrinter,
  ups: IconServer,
  pdu: IconServer,
  pos_terminal: IconWorkstation,
  wireless_bridge: IconAccessPoint,
  // Energy
  ev_charger: IconIoT,
  solar_inverter: IconIoT,
  // Other
  drone: IconIoT,
  // Transportation
  vehicle: IconIoT,
  vehicle_diagnostic: IconIoT,
  dashcam: IconCamera,
  marine_device: IconIoT,
  gps_tracker: IconIoT,
  // Satellite / Tactical
  satellite_terminal: IconMeshRouter,
  tactical_radio: IconIoT,
  body_camera: IconCamera,
  crypto_device: IconFirewall,
  // Scientific / Education
  lab_instrument: IconWorkstation,
  weather_station: IconIoT,
  sbc: IconIoT,
  interactive_display: IconSmartDisplay,
  // Enterprise / Retail
  atm: IconWorkstation,
  vending_machine: IconIoT,
  time_clock: IconIoT,
  handheld_scanner: IconIoT,
  wireless_presentation: IconStreamingDevice,
  kiosk: IconWorkstation,
  // Security / Access
  access_control: IconSmartLock,
  // Industrial
  plc: IconIoT,
  rtu: IconIoT,
  hmi: IconSmartDisplay,
  industrial_switch: IconSwitch,
  industrial_robot: IconIoT,
  cnc_machine: IconIoT,
  power_meter: IconIoT,
  building_automation: IconSmartHome,
  fire_alarm: IconSmartHome,
  elevator_controller: IconIoT,
  // Medical
  medical_device: IconIoT,
  // Missing infrastructure types
  cable_modem: IconRouter,
  network_device: IconSwitch,
  av_switcher: IconSwitch,
  // Missing IoT types
  robot_vacuum: IconSmartHome,
  smart_scale: IconIoT,
  garage_controller: IconSmartHome,
  garage_door_opener: IconSmartHome,
  smart_blinds: IconSmartHome,
  smart_fan: IconSmartHome,
  smart_valve: IconIoT,
  water_leak_sensor: IconIoT,
  motion_sensor: IconIoT,
  contact_sensor: IconIoT,
  humidity_sensor: IconIoT,
  air_quality_monitor: IconIoT,
  smart_sprinkler: IconIoT,
  smart_switch: IconSmartPlug,
  media_device: IconStreamingDevice,
  wireless_earbuds: IconWearable,
  // Catch-all
  unknown: IconUnknown,
};

export function getDeviceIcon(deviceType: string | null | undefined): React.ComponentType<IconProps> {
  return DEVICE_ICON_MAP[deviceType ?? ""] ?? IconUnknown;
}
