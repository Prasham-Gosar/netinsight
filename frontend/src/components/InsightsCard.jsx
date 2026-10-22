import React from 'react'
import Card from './Card'

const ICON = { good: '✓', info: 'i', warn: '!', bad: '✕' }

export default function InsightsCard({ insights }) {
  return (
    <Card title="Insights" subtitle="Plain-English observations from measured data">
      <ul className="insights">
        {insights.map((i) => (
          <li key={i.title + i.text} className={i.level}>
            <span className="ico">{ICON[i.level] || 'i'}</span>
            <div>
              <b>{i.title}</b>
              <p>{i.text}</p>
            </div>
          </li>
        ))}
        {insights.length === 0 && <li className="muted small">Nothing to report yet.</li>}
      </ul>
    </Card>
  )
}
