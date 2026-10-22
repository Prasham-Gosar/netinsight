import React, { useMemo, useState } from 'react'
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import Card from './Card'
import { COLORS, fmtBytes } from '../format'
import { usePolling } from '../hooks'

const LABEL = { minutes: 'Last 60 minutes', hours: 'Last 24 hours', days: 'Last 7 days' }

function shortLabel(bucket, g) {
  if (g === 'minutes') return bucket.slice(11, 16)
  if (g === 'hours') return `${bucket.slice(11, 13)}:00`
  return bucket.slice(5)
}

export default function TimelineCard() {
  const [g, setG] = useState('minutes')
  const { data, error } = usePolling(`/api/history/timeline?granularity=${g}`, 15000)
  const rows = useMemo(() => (data || []).map((r) => ({ ...r, label: shortLabel(r.bucket, g) })), [data, g])

  const tabs = (
    <div className="seg">
      {Object.keys(LABEL).map((k) => (
        <button key={k} className={g === k ? 'on' : ''} onClick={() => setG(k)}>
          {k}
        </button>
      ))}
    </div>
  )
  return (
    <Card title="Traffic Timeline" subtitle={`${LABEL[g]} · stored history (updates every few seconds)`} right={tabs}>
      <div className="chart" style={{ height: 230 }}>
        {error ? (
          <p className="muted small empty">History unavailable ({error}). Is the database enabled?</p>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={rows} margin={{ top: 6, right: 8, left: -6, bottom: 0 }}>
              <CartesianGrid stroke="#222c48" strokeDasharray="3 3" vertical={false} />
              <XAxis dataKey="label" tick={{ fill: '#8b97b8', fontSize: 11 }} interval="preserveStartEnd" minTickGap={24} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: '#8b97b8', fontSize: 11 }} tickFormatter={(v) => fmtBytes(v)} axisLine={false} tickLine={false} width={62} />
              <Tooltip
                contentStyle={{ background: '#0b1020', border: '1px solid #222c48', borderRadius: 8 }}
                formatter={(v, n) => [fmtBytes(v), n === 'in' ? 'Download' : 'Upload']}
              />
              <Bar dataKey="in" stackId="a" fill={COLORS.cyan} isAnimationActive={false} />
              <Bar dataKey="out" stackId="a" fill={COLORS.violet} isAnimationActive={false} />
            </BarChart>
          </ResponsiveContainer>
        )}
      </div>
    </Card>
  )
}
