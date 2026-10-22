import React, { useMemo } from 'react'
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import Card from './Card'
import { COLORS, clock, fmtRate } from '../format'

export default function BandwidthCard({ series, rate }) {
  const data = useMemo(
    () => series.map((p) => ({ label: clock(p.t), down: (p.in * 8) / 1e6, up: (p.out * 8) / 1e6, local: (p.local * 8) / 1e6 })),
    [series],
  )
  return (
    <Card
      title="Live Bandwidth"
      subtitle="Last 2 minutes, per second"
      right={
        <div className="rates">
          <span style={{ color: COLORS.cyan }}>↓ {fmtRate(rate.in_bps)}</span>
          <span style={{ color: COLORS.violet }}>↑ {fmtRate(rate.out_bps)}</span>
        </div>
      }
    >
      <div className="chart" style={{ height: 230 }}>
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ top: 6, right: 8, left: -12, bottom: 0 }}>
            <defs>
              <linearGradient id="gDown" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={COLORS.cyan} stopOpacity={0.5} />
                <stop offset="100%" stopColor={COLORS.cyan} stopOpacity={0.02} />
              </linearGradient>
              <linearGradient id="gUp" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={COLORS.violet} stopOpacity={0.5} />
                <stop offset="100%" stopColor={COLORS.violet} stopOpacity={0.02} />
              </linearGradient>
            </defs>
            <CartesianGrid stroke="#222c48" strokeDasharray="3 3" vertical={false} />
            <XAxis dataKey="label" tick={{ fill: '#8b97b8', fontSize: 11 }} interval={19} axisLine={false} tickLine={false} />
            <YAxis tick={{ fill: '#8b97b8', fontSize: 11 }} tickFormatter={(v) => `${v.toFixed(v < 10 ? 1 : 0)}`} unit=" M" axisLine={false} tickLine={false} />
            <Tooltip
              contentStyle={{ background: '#0b1020', border: '1px solid #222c48', borderRadius: 8 }}
              formatter={(v, name) => [`${Number(v).toFixed(2)} Mbps`, name === 'down' ? 'Download' : 'Upload']}
            />
            <Area type="monotone" dataKey="down" stroke={COLORS.cyan} fill="url(#gDown)" strokeWidth={2} isAnimationActive={false} />
            <Area type="monotone" dataKey="up" stroke={COLORS.violet} fill="url(#gUp)" strokeWidth={2} isAnimationActive={false} />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </Card>
  )
}
