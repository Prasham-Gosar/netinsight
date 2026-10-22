// Small formatting helpers shared by all components.

export function fmtBytes(n) {
  if (n == null || Number.isNaN(n)) return '–'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let v = Number(n)
  let i = 0
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return `${i === 0 || v >= 100 ? v.toFixed(0) : v.toFixed(1)} ${units[i]}`
}

// bytes/second -> "x.x Mbps" (networking convention is bits per second)
export function fmtRate(bytesPerSec) {
  const bits = (bytesPerSec || 0) * 8
  if (bits >= 1e9) return `${(bits / 1e9).toFixed(2)} Gbps`
  if (bits >= 1e6) return `${(bits / 1e6).toFixed(1)} Mbps`
  if (bits >= 1e3) return `${(bits / 1e3).toFixed(0)} kbps`
  return `${bits.toFixed(0)} bps`
}

export function fmtMs(v) {
  if (v == null) return '–'
  return v >= 100 ? `${v.toFixed(0)} ms` : `${v.toFixed(1)} ms`
}

export function fmtPct(v, digits = 1) {
  if (v == null) return '–'
  return `${Number(v).toFixed(digits)}%`
}

export function fmtDuration(seconds) {
  const s = Math.max(0, Math.floor(seconds || 0))
  const h = Math.floor(s / 3600)
  const m = Math.floor((s % 3600) / 60)
  const sec = s % 60
  if (h) return `${h}h ${m}m`
  if (m) return `${m}m ${sec}s`
  return `${sec}s`
}

export function clock(epochSeconds) {
  const d = new Date(epochSeconds * 1000)
  return d.toLocaleTimeString([], { hour12: false })
}

export const COLORS = {
  cyan: '#4cc9f0',
  indigo: '#7aa2ff',
  violet: '#b388ff',
  green: '#3ddc97',
  lime: '#a3e635',
  amber: '#ffb454',
  red: '#ff5c7a',
  gray: '#8b97b8',
}

export const FAMILY_COLORS = {
  TCP: COLORS.cyan,
  UDP: COLORS.violet,
  DNS: COLORS.green,
  ICMP: COLORS.amber,
  ARP: COLORS.red,
  Other: COLORS.gray,
}

export const APP_PALETTE = [COLORS.cyan, COLORS.violet, COLORS.green, COLORS.amber, COLORS.red, COLORS.indigo, COLORS.lime, COLORS.gray]
