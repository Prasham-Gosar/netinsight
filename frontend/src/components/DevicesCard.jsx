import React from 'react'
import Card from './Card'
import { fmtBytes } from '../format'

export default function DevicesCard({ devices, totals }) {
  const connected = totals?.devices ?? devices.length
  const active = totals?.active_devices ?? devices.filter((device) => device.active).length
  return (
    <Card title="Devices" subtitle={`${connected} connected · ${active} active now · discovered via ARP & observed traffic`}>
      <div className="scroll">
        <table>
          <thead>
            <tr>
              <th>Device</th>
              <th>IP</th>
              <th className="num">↓ In</th>
              <th className="num">↑ Out</th>
            </tr>
          </thead>
          <tbody>
            {devices.map((d) => (
              <tr key={d.key}>
                <td>
                  <span className={`dot ${d.active ? 'on' : 'off'}`} /> {d.name}
                  <div className="muted small">{d.vendor || d.mac || ''}</div>
                </td>
                <td className="mono">{d.ip}</td>
                <td className="num">{fmtBytes(d.bytes_in)}</td>
                <td className="num">{fmtBytes(d.bytes_out)}</td>
              </tr>
            ))}
            {devices.length === 0 && (
              <tr>
                <td colSpan={4} className="muted small">
                  No devices seen yet
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      <p className="muted small note">
        On Wi-Fi your PC mostly sees its own traffic, so other devices may show little data. Capturing on a router or mirrored port shows more.
      </p>
    </Card>
  )
}
