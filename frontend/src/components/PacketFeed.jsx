import React, { useRef, useState } from 'react'
import Card from './Card'
import { FAMILY_COLORS, COLORS, fmtBytes } from '../format'

export default function PacketFeed({ packets }) {
  const [paused, setPaused] = useState(false)
  const frozen = useRef(packets)
  if (!paused) frozen.current = packets
  const rows = frozen.current

  return (
    <Card
      title="Live Packet Feed"
      subtitle="Every packet, translated into plain English"
      right={
        <button className="btn" onClick={() => setPaused(!paused)}>
          {paused ? '▶ Resume' : '⏸ Pause'}
        </button>
      }
    >
      <ul className="feed">
        {rows.slice(0, 14).map((p) => (
          <li key={p.n}>
            <div className="feed-row mono">
              <span className="muted">#{p.n}</span>
              <span>{p.time}</span>
              <span className="tag" style={{ background: `${FAMILY_COLORS[p.family] || COLORS.gray}26`, color: FAMILY_COLORS[p.family] || COLORS.gray }}>
                {p.protocol}
              </span>
              <span className="ellipsis">
                {p.src} → {p.dst}
              </span>
              <span className="muted">{fmtBytes(p.size)}</span>
              <span className="muted">{p.flags || ''}</span>
              <span className="app">{p.app}</span>
            </div>
            <div className="explain">{p.explanation}</div>
          </li>
        ))}
        {rows.length === 0 && <li className="muted small">Waiting for packets…</li>}
      </ul>
    </Card>
  )
}
