import React from 'react'
import { fmtDuration } from '../format'

export default function Header({ meta, totals, error }) {
  const live = meta && meta.mode === 'live'
  return (
    <header className="topbar">
      <div className="brand">
        <div className="logo">
          <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M2 12h4l3-8 4 16 3-8h6" />
          </svg>
        </div>
        <div>
          <h1>NetInsight</h1>
          <p className="muted small">Network intelligence dashboard</p>
        </div>
      </div>
      <div className="pills">
        {error ? (
          <span className="pill bad">Backend unreachable</span>
        ) : meta ? (
          <>
            <span className={`pill ${live ? 'good' : 'info'}`}>
              <span className="dot pulse" /> {live ? 'LIVE CAPTURE' : 'SIMULATION'}
            </span>
            <span className="pill">{meta.interface || '—'}</span>
            <span className="pill">Uptime {fmtDuration(meta.uptime_s)}</span>
            {totals && totals.dropped > 0 && <span className="pill warn">Dropped {totals.dropped} pkts</span>}
          </>
        ) : (
          <span className="pill">Connecting…</span>
        )}
      </div>
    </header>
  )
}
