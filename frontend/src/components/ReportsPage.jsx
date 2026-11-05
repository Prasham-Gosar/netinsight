import React, { useEffect, useState } from 'react'
import { getJSON } from '../api'

const date = (value) => value ? new Date(value).toLocaleString() : '—'

export default function ReportsPage() {
  const [reports, setReports] = useState([])
  const [selected, setSelected] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    getJSON('/api/reports').then(items => {
      setReports(items)
      if (items[0]) return getJSON(`/api/reports/${items[0].report_id}`).then(setSelected)
    }).catch(e => setError(e.message || String(e)))
  }, [])

  const select = (report) => getJSON(`/api/reports/${report.report_id}`).then(setSelected).catch(e => setError(e.message || String(e)))
  const snapshot = selected && selected.snapshot
  return (
    <main className="reports-page">
      <div className="reports-heading">
        <div><h2>My Generated Reports</h2><p className="muted">Snapshots of your network health and traffic insights.</p></div>
      </div>
      {error && <div className="banner">{error}</div>}
      <div className="report-split">
        <section className="report-list card">
          <div className="card-head"><h2>Report history</h2><span className="muted small">{reports.length} reports</span></div>
          {reports.length === 0 ? <div className="empty muted">No reports yet. Generate one from the dashboard.</div> : (
            <div className="scroll"><table><thead><tr><th>Report ID</th><th>Generated</th><th>Health</th><th>Status</th></tr></thead>
              <tbody>{reports.map(report => <tr key={report.report_id} className={`report-row ${selected && selected.report_id === report.report_id ? 'selected' : ''}`} onClick={() => select(report)}>
                <td className="mono">{report.report_id}</td><td>{date(report.generated_at)}</td><td>{report.health_score ?? '—'}</td><td><span className="state ready">{report.status}</span></td>
              </tr>)}</tbody>
            </table></div>
          )}
        </section>
        <section className="report-preview card">
          {!snapshot ? <div className="empty muted">Select a report to preview it here.</div> : <>
            <div className="card-head"><div><h2>{selected.report_id}</h2><p className="muted small">Generated {date(selected.generated_at)}</p></div>
              <a className="btn" href={`/api/reports/${selected.report_id}/pdf`}>Download PDF</a></div>
            <div className="preview-score"><span className="muted">Network health</span><strong>{snapshot.health.score ?? '—'}</strong><span>{snapshot.health.status || 'Unknown'}</span></div>
            <div className="metric-grid"><div className="metric"><div><div className="muted small">Traffic</div><div className="metric-val">{snapshot.totals.bytes ?? 0} bytes</div></div></div>
              <div className="metric"><div><div className="muted small">Packets</div><div className="metric-val">{snapshot.totals.packets ?? 0}</div></div></div>
              <div className="metric"><div><div className="muted small">Active devices</div><div className="metric-val">{snapshot.totals.active_devices ?? 0}</div></div></div></div>
            <div className="preview-columns"><div><h2>Top applications</h2><ul className="report-bullets">{snapshot.applications.map(a => <li key={a.name}><span>{a.name}</span><b>{a.bytes ?? 0} bytes</b></li>)}</ul></div>
              <div><h2>Anomalies & insights</h2><ul className="report-bullets">{[...(snapshot.anomalies || []).map(a => a.title || a.message), ...(snapshot.insights || [])].slice(0, 8).map((text, i) => <li key={i}>{typeof text === 'string' ? text : JSON.stringify(text)}</li>)}</ul></div></div>
            {snapshot.historical && <div className="historical-report">
              <h2>Historical context · last 30 days</h2>
              <div className="metric-grid">
                <div className="metric"><div><div className="muted small">Stored traffic</div><div className="metric-val">{snapshot.historical.summary.bytes_in + snapshot.historical.summary.bytes_out + snapshot.historical.summary.bytes_local} bytes</div></div></div>
                <div className="metric"><div><div className="muted small">Stored health samples</div><div className="metric-val">{snapshot.historical.health.length}</div></div></div>
                <div className="metric"><div><div className="muted small">Stored anomalies</div><div className="metric-val">{snapshot.historical.anomalies.length}</div></div></div>
              </div>
            </div>}
          </>}
        </section>
      </div>
    </main>
  )
}
