import React from 'react'
import { fmtBytes } from '../format'

function Kpi({ label, value, hint, tone }) {
  return (
    <div className={`kpi ${tone || ''}`}>
      <div className="muted small">{label}</div>
      <div className="kpi-val">{value}</div>
      {hint && <div className="muted small">{hint}</div>}
    </div>
  )
}

export default function Kpis({ totals }) {
  return (
    <div className="kpis">
      <Kpi label="Total traffic" value={fmtBytes(totals.bytes)} hint={`↓ ${fmtBytes(totals.bytes_in)}  ↑ ${fmtBytes(totals.bytes_out)}`} />
      <Kpi label="Packets analysed" value={totals.packets.toLocaleString()} hint={`${totals.flows_active} active flows`} />
      <Kpi label="Devices" value={totals.devices} hint={`${totals.active_devices} active now`} />
      <Kpi label="Active alerts" value={totals.alerts_active} tone={totals.alerts_active > 0 ? 'alert' : ''} hint={totals.alerts_active ? 'needs a look' : 'all quiet'} />
    </div>
  )
}
