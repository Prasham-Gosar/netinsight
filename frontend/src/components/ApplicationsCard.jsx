import React from 'react'
import Card from './Card'
import { APP_PALETTE, fmtBytes } from '../format'

export default function ApplicationsCard({ apps }) {
  return (
    <Card title="Top Applications" subtitle="Best-effort, from DNS names & TLS server names">
      <ul className="bars">
        {apps.map((a, i) => (
          <li key={a.name}>
            <div className="bar-top">
              <span>{a.name}</span>
              <span className="muted small">
                {fmtBytes(a.bytes)} · <b>{a.percent.toFixed(1)}%</b>
              </span>
            </div>
            <div className="bar-track">
              <div className="bar-fill" style={{ width: `${Math.max(2, a.percent)}%`, background: APP_PALETTE[i % APP_PALETTE.length] }} />
            </div>
          </li>
        ))}
        {apps.length === 0 && <li className="muted small">No traffic yet</li>}
      </ul>
    </Card>
  )
}
