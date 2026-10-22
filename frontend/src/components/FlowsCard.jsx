import React from 'react'
import Card from './Card'
import { fmtBytes, fmtMs } from '../format'

export default function FlowsCard({ flows }) {
  return (
    <Card title="Active Flows" subtitle="Conversations between two endpoints, largest first">
      <div className="scroll">
        <table>
          <thead>
            <tr>
              <th>Client → Server</th>
              <th>App</th>
              <th>State</th>
              <th className="num">RTT</th>
              <th className="num">Retrans.</th>
              <th className="num">Packets</th>
              <th className="num">Traffic</th>
            </tr>
          </thead>
          <tbody>
            {flows.map((f) => (
              <tr key={`${f.proto}-${f.client}-${f.server}`}>
                <td className="mono">
                  {f.client} → {f.server}
                  <div className="muted small ellipsis">{f.domain || f.app_protocol}</div>
                </td>
                <td>{f.app}</td>
                <td>
                  <span className={`state ${f.state}`}>{f.proto === 'UDP' ? 'UDP' : f.state}</span>
                </td>
                <td className="num">{f.rtt_ms == null ? '–' : fmtMs(f.rtt_ms)}</td>
                <td className="num">{f.retransmissions}</td>
                <td className="num">{f.packets.toLocaleString()}</td>
                <td className="num">{fmtBytes(f.bytes)}</td>
              </tr>
            ))}
            {flows.length === 0 && (
              <tr>
                <td colSpan={7} className="muted small">
                  No flows yet
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </Card>
  )
}
