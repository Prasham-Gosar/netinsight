import React, { useState } from 'react'
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from 'recharts'
import Card from './Card'
import { FAMILY_COLORS, COLORS, fmtBytes } from '../format'

export default function ProtocolCard({ families }) {
  const [by, setBy] = useState('packets')
  const data = families.map((f) => ({
    name: f.name,
    value: by === 'packets' ? f.packets : f.bytes,
    pct: by === 'packets' ? f.percent_packets : f.percent_bytes,
  }))
  const toggle = (
    <div className="seg">
      {['packets', 'bytes'].map((k) => (
        <button key={k} className={by === k ? 'on' : ''} onClick={() => setBy(k)}>
          {k}
        </button>
      ))}
    </div>
  )
  return (
    <Card title="Protocol Distribution" subtitle="Share of traffic by protocol family" right={toggle}>
      <div className="donut-row">
        <div className="chart" style={{ height: 170, width: 170 }}>
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie data={data} dataKey="value" innerRadius={48} outerRadius={78} paddingAngle={2} stroke="none" isAnimationActive={false}>
                {data.map((d) => (
                  <Cell key={d.name} fill={FAMILY_COLORS[d.name] || COLORS.gray} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{ background: '#0b1020', border: '1px solid #222c48', borderRadius: 8 }}
                formatter={(v, n) => [by === 'bytes' ? fmtBytes(v) : Number(v).toLocaleString(), n]}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>
        <ul className="legend">
          {data.map((d) => (
            <li key={d.name}>
              <span className="swatch" style={{ background: FAMILY_COLORS[d.name] || COLORS.gray }} />
              <span>{d.name}</span>
              <b>{d.pct.toFixed(1)}%</b>
            </li>
          ))}
          {data.length === 0 && <li className="muted small">No traffic yet</li>}
        </ul>
      </div>
    </Card>
  )
}
