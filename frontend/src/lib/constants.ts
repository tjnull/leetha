// frontend/src/lib/constants.ts

export const DEVICE_TYPE_COLORS: Record<string, string> = {
  // Internet/WAN
  internet: "#f97316",
  // Infrastructure
  router: "#f87171",
  gateway: "#f87171",
  switch: "#fb923c",
  access_point: "#fbbf24",
  mesh_router: "#fbbf24",
  wearable: "#e879f9",
  voip_phone: "#60a5fa",
  firewall: "#f87171",
  load_balancer: "#fb923c",
  // Compute
  server: "#34d399",
  hypervisor: "#34d399",
  container: "#34d399",
  container_host: "#34d399",
  kubernetes_node: "#34d399",
  kvm_host: "#34d399",
  hyper_v: "#34d399",
  ai_gateway: "#34d399",
  // Desktop
  workstation: "#60a5fa",
  laptop: "#a78bfa",
  desktop: "#818cf8",
  computer: "#a78bfa",
  // Mobile
  mobile: "#e879f9",
  smartphone: "#f0abfc",
  phone: "#f0abfc",
  tablet: "#c084fc",
  // Entertainment
  smart_tv: "#2dd4bf",
  smart_speaker: "#67e8f9",
  smart_display: "#2dd4bf",
  media_player: "#2dd4bf",
  streaming_device: "#2dd4bf",
  game_console: "#a78bfa",
  // Office
  printer: "#fbbf24",
  scanner: "#fbbf24",
  // Security
  camera: "#fcd34d",
  ip_camera: "#fcd34d",
  // Storage
  nas: "#34d399",
  // IoT / Smart Home
  iot: "#67e8f9",
  smart_home: "#67e8f9",
  thermostat: "#67e8f9",
  doorbell: "#fcd34d",
  smart_lighting: "#fbbf24",
  smart_plug: "#67e8f9",
  smart_lock: "#fcd34d",
  embedded: "#67e8f9",
  // Appliances / Home
  appliance: "#fb923c",
  smoke_detector: "#f87171",
  garage_door: "#67e8f9",
  irrigation: "#34d399",
  air_purifier: "#67e8f9",
  baby_monitor: "#f0abfc",
  pet_device: "#fbbf24",
  // Entertainment / AV
  projector: "#2dd4bf",
  media_server: "#34d399",
  digital_signage: "#2dd4bf",
  video_conferencing: "#60a5fa",
  // Industrial / Enterprise
  "3d_printer": "#fbbf24",
  ups: "#fb923c",
  pdu: "#fb923c",
  pos_terminal: "#60a5fa",
  wireless_bridge: "#fbbf24",
  // Energy
  ev_charger: "#34d399",
  solar_inverter: "#fbbf24",
  // Other
  drone: "#a78bfa",
  // Transportation
  vehicle: "#60a5fa",
  vehicle_diagnostic: "#60a5fa",
  dashcam: "#fcd34d",
  marine_device: "#22d3ee",
  gps_tracker: "#34d399",
  // Satellite / Tactical
  satellite_terminal: "#a78bfa",
  tactical_radio: "#f87171",
  body_camera: "#fcd34d",
  crypto_device: "#f87171",
  // Scientific / Education
  lab_instrument: "#34d399",
  weather_station: "#22d3ee",
  sbc: "#a78bfa",
  interactive_display: "#2dd4bf",
  // Enterprise / Retail
  atm: "#60a5fa",
  vending_machine: "#67e8f9",
  time_clock: "#64748b",
  handheld_scanner: "#fbbf24",
  wireless_presentation: "#2dd4bf",
  kiosk: "#60a5fa",
  // Security / Access
  access_control: "#fcd34d",
  // Industrial
  plc: "#fb923c",
  rtu: "#fb923c",
  hmi: "#fb923c",
  industrial_switch: "#fb923c",
  industrial_robot: "#fb923c",
  cnc_machine: "#fb923c",
  power_meter: "#fbbf24",
  building_automation: "#67e8f9",
  fire_alarm: "#f87171",
  elevator_controller: "#64748b",
  // Medical
  medical_device: "#f87171",
  // Missing infrastructure types
  cable_modem: "#f87171",
  network_device: "#fb923c",
  av_switcher: "#fb923c",
  // Missing IoT types
  robot_vacuum: "#67e8f9",
  smart_scale: "#67e8f9",
  garage_controller: "#67e8f9",
  garage_door_opener: "#67e8f9",
  smart_blinds: "#67e8f9",
  smart_fan: "#67e8f9",
  smart_valve: "#67e8f9",
  water_leak_sensor: "#67e8f9",
  motion_sensor: "#67e8f9",
  contact_sensor: "#67e8f9",
  humidity_sensor: "#67e8f9",
  air_quality_monitor: "#67e8f9",
  smart_sprinkler: "#34d399",
  smart_switch: "#67e8f9",
  media_device: "#2dd4bf",
  wireless_earbuds: "#e879f9",
};

export function getDeviceTypeColor(deviceType: string | null | undefined): string {
  return DEVICE_TYPE_COLORS[deviceType ?? ""] ?? "#64748b";
}

export const NAV_ITEMS = {
  recon: [
    { path: "/", label: "Overview", icon: "LayoutDashboard", page: "dashboard" },
    { path: "/inventory", label: "Inventory", icon: "Monitor", page: "inventory", badge: "deviceCount" },
    { path: "/alerts", label: "Findings", icon: "Bell", page: "findings", badge: "alertCount" },
    { path: "/detections", label: "Detections", icon: "ShieldAlert", page: "detections" },
    { path: "/exposure", label: "Exposure", icon: "Shield", page: "exposure" },
    { path: "/stream", label: "Stream", icon: "Terminal", page: "stream" },
  ],
  intelligence: [
    { path: "/feeds", label: "Sources", icon: "RefreshCw", page: "feeds" },
    { path: "/rules", label: "Rules", icon: "AlignLeft", page: "rules" },
    { path: "/adapters", label: "Adapters", icon: "Activity", page: "adapters" },
    { path: "/settings", label: "Settings", icon: "Settings", page: "settings" },
  ],
  reference: [
    { path: "/docs", label: "Knowledge Base", icon: "BookOpen", page: "docs" },
  ],
} as const;
