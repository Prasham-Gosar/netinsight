import React, { useState } from 'react'
import Card from './Card'

function Alert({ a }) {
  const [open, setOpen] = useState(false)
  return (
    <li className={`alert ${a.severity} ${a.active ? '' : 'resolved'}`}>
      <div className="alert-head">
        <b>{a.title}</b>
        <span className="muted small">
          {a.time} · {a.active ? 'active' : 'resolved'}
        </span>
      </div>
      <p>{a.message}</p>
      {a.peak_ratio > a.ratio && (
        <p className="muted small">
          Peaked at ≈{a.peak_ratio}× baseline ({a.peak_rate} {a.unit}).
        </p>
      )}
      {a.context && a.context.length > 0 && (
        <ul className="ctx">
          {a.context.map((c) => (
            <li key={c}>{c}</li>
          ))}
        </ul>
      )}
      <p className="muted small">{a.advice}</p>
      <button className="link" onClick={() => setOpen(!open)}>
        {open ? 'Hide' : 'Possible causes'}
      </button>
      {open && (
        <ul className="ctx">
          {a.causes.map((c) => (
            <li key={c}>{c}</li>
          ))}
        </ul>
      )}
    </li>
  )
}

export default function AlertsCard({ alerts, baseline }) {
  const learning = baseline && !baseline.ready
  return (
    <Card
      title="Anomaly Alerts"
      subtitle="Compares the last 10 s with the previous 5 minutes"
      right={learning ? <span className="pill info">Learning baseline {Math.min(baseline.seconds, baseline.needed)}/{baseline.needed}s</span> : null}
    >
      {alerts.length === 0 ? (
        <p className="muted small empty">{learning ? 'Learning what “normal” looks like before raising alerts…' : 'No unusual activity detected.'}</p>
      ) : (
        <ul className="alerts">
          {alerts.map((a) => (
            <Alert key={a.id} a={a} />
          ))}
        </ul>
      )}
    </Card>
  )
}
