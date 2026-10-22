import React from 'react'
import Card from './Card'
import { fmtBytes } from '../format'

export default function TopIpsCard({ ips }) {
  return (
    <Card title="Top Destinations" subtitle="Remote addresses by traffic volume">
      <div className="scroll">
        <table>
          <thead>
            <tr>
              <th>Destination</th>
              <th>Application</th>
              <th className="num">Traffic</th>
            </tr>
          </thead>
          <tbody>
            {ips.map((r) => (
              <tr key={r.ip}>
                <td>
                  <div className="mono">{r.ip}</div>
                  <div className="muted small ellipsis" title={r.domain || ''}>
                    {r.domain || 'name unknown'}
                  </div>
                </td>
                <td>{r.app || '—'}</td>
                <td className="num">{fmtBytes(r.bytes)}</td>
              </tr>
            ))}
            {ips.length === 0 && (
              <tr>
                <td colSpan={3} className="muted small">
                  No traffic yet
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </Card>
  )
}
