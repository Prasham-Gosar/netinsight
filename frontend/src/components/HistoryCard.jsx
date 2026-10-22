import React from 'react'
import Card from './Card'
import { fmtBytes } from '../format'
import { usePolling } from '../hooks'

function hhmm(s) {
  return s ? s.slice(11, 16) : ''
}

export default function HistoryCard() {
  const { data, error } = usePolling('/api/history/answers', 15000)
  const tiles = []
  if (data) {
    const t = data.traffic_today
    tiles.push({ q: 'How much traffic was used today?', a: fmtBytes(t.total), d: `↓ ${fmtBytes(t.bytes_in)} · ↑ ${fmtBytes(t.bytes_out)}` })
    const app = data.top_application
    tiles.push({ q: 'Which application used the most bandwidth?', a: app ? app.name : '—', d: app ? `${fmtBytes(app.bytes)} (${app.percent}%)` : 'no data yet' })
    const dev = data.top_device
    tiles.push({ q: 'Which device consumed the most?', a: dev ? dev.name : '—', d: dev ? `${fmtBytes(dev.bytes)} (${dev.percent}%)` : 'no data yet' })
    const slow = data.slowest_minute
    tiles.push({ q: 'When was the network slowest?', a: slow ? hhmm(slow.time) : '—', d: slow ? `avg latency ${slow.latency_ms} ms` : 'not enough data yet' })
    const loss = data.highest_loss_minute
    tiles.push({
      q: 'Did packet loss rise at a particular time?',
      a: loss ? (loss.packet_loss_pct >= 1 ? `Yes, around ${hhmm(loss.time)}` : 'No notable loss') : '—',
      d: loss ? `peak estimate ${loss.packet_loss_pct}%` : 'not enough data yet',
    })
  }
  return (
    <Card title="Ask Your Network" subtitle="Answers computed from stored history">
      {error ? (
        <p className="muted small empty">History unavailable ({error}).</p>
      ) : (
        <div className="tiles">
          {tiles.map((t) => (
            <div key={t.q} className="tile">
              <div className="muted small">{t.q}</div>
              <div className="tile-a">{t.a}</div>
              <div className="muted small">{t.d}</div>
            </div>
          ))}
        </div>
      )}
    </Card>
  )
}
