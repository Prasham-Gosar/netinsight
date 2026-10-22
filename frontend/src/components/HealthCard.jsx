import React from 'react'
import Card from './Card'
import { COLORS, fmtMs, fmtPct } from '../format'

const STATUS_COLOR = { green: COLORS.green, lime: COLORS.lime, amber: COLORS.amber, red: COLORS.red, gray: COLORS.gray }
const ARC = Math.PI * 90

function fmtValue(c) {
  if (c.value == null) return '–'
  return c.unit === 'ms' ? fmtMs(c.value) : fmtPct(c.value)
}

function severity(c) {
  if (!c.measured) return 'na'
  const r = c.penalty / c.max_penalty
  return r < 0.15 ? 'ok' : r < 0.6 ? 'mid' : 'bad'
}

export default function HealthCard({ health }) {
  const score = health.score
  const color = STATUS_COLOR[health.color] || COLORS.gray
  const offset = ARC * (1 - (score == null ? 0 : score) / 100)
  const shown = ['latency', 'packet_loss', 'retransmissions', 'dns_latency', 'dup_acks', 'conn_failures']
  const comps = shown.map((k) => health.components.find((c) => c.key === k)).filter(Boolean)

  return (
    <Card title="Network Health" subtitle={`Based on the last ${health.window_s}s of measured traffic`}>
      <div className="gauge-wrap">
        <svg viewBox="0 0 220 125" className="gauge" role="img" aria-label={`Network health ${score ?? 'unknown'} out of 100`}>
          <path d="M 20 110 A 90 90 0 0 1 200 110" className="gauge-track" />
          <path d="M 20 110 A 90 90 0 0 1 200 110" className="gauge-fill" style={{ stroke: color, strokeDasharray: ARC, strokeDashoffset: offset }} />
          <text x="110" y="98" textAnchor="middle" className="gauge-score" style={{ fill: color }}>
            {score == null ? '…' : score}
          </text>
          <text x="110" y="118" textAnchor="middle" className="gauge-sub">
            {score == null ? 'collecting data' : 'out of 100'}
          </text>
        </svg>
        <div className="gauge-status" style={{ color }}>
          {health.status}
        </div>
      </div>

      <div className="metric-grid">
        {comps.map((c) => (
          <div key={c.key} className="metric" title={c.measured ? `Penalty ${c.penalty}/${c.max_penalty} points` : 'Not enough data yet'}>
            <span className={`sev ${severity(c)}`} />
            <div>
              <div className="metric-val">{fmtValue(c)}</div>
              <div className="muted small">{c.label}</div>
            </div>
          </div>
        ))}
      </div>

      <div className="issues">
        {health.issues.length === 0 ? (
          <span className="muted small">{score == null ? 'Waiting for enough traffic to score the network.' : 'No issues detected.'}</span>
        ) : (
          health.issues.map((i) => (
            <span key={i} className="chip warn">
              • {i}
            </span>
          ))
        )}
      </div>

      <details className="how">
        <summary>How is this score calculated?</summary>
        <p className="muted small">Start at 100, lose points per metric (linear between “fine” and “bad”). Metrics without enough samples are skipped.</p>
        <table className="mini">
          <thead>
            <tr>
              <th>Metric</th>
              <th>Fine → bad</th>
              <th>Lost</th>
            </tr>
          </thead>
          <tbody>
            {health.components.map((c) => (
              <tr key={c.key}>
                <td>{c.label}</td>
                <td>
                  {c.good}→{c.bad} {c.unit}
                </td>
                <td>
                  {c.measured ? c.penalty : '–'} / {c.max_penalty}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </details>
    </Card>
  )
}
