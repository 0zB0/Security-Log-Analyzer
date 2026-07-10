export const SAMPLE_OPTIONS = [
  { id: "auth-ssh-compromise", label: "Auth SSH compromise" },
  { id: "suricata-alert-burst", label: "Suricata alert burst" },
  { id: "suricata-c2-http-dns", label: "Suricata C2 DNS" },
  { id: "zeek-port-scan", label: "Zeek port scan" },
  { id: "zeek-dns-http-notice", label: "Zeek DNS HTTP notice" },
  { id: "cloudtrail-iam-risk", label: "CloudTrail IAM risk" },
  { id: "kubernetes-audit-risk", label: "Kubernetes audit risk" },
  { id: "windows-security-risk", label: "Windows Security risk" },
];

export const CAPTURE_PRESETS = [
  {
    id: "loopback-port-scan",
    label: "Loopback port scan proof",
    interfaceName: "lo",
    captureFilter: "tcp and dst portrange 33000-33020",
  },
  {
    id: "cloudflare-warp",
    label: "CloudflareWARP metadata",
    interfaceName: "CloudflareWARP",
    captureFilter: "ip or ip6",
  },
  {
    id: "wireguard",
    label: "WireGuard metadata",
    interfaceName: "wg0",
    captureFilter: "ip or ip6",
  },
  {
    id: "dns-only",
    label: "DNS only",
    interfaceName: "lo",
    captureFilter: "udp port 53 or tcp port 53",
  },
  {
    id: "admin-services",
    label: "TCP admin services",
    interfaceName: "lo",
    captureFilter: "tcp and (dst port 22 or dst port 2222 or dst port 3389)",
  },
];
