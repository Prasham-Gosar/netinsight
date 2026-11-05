import React from 'react'
import PacketFeed from './PacketFeed'
import FlowsCard from './FlowsCard'

export default function PacketFeedPage({ data, error }) {
  return (
    <main className="packet-page">
      <div className="packet-page-heading">
        <div>
          <h2>Packet Feed</h2>
          <p className="muted">Inspect live packet activity and the conversations currently moving through your network.</p>
        </div>
        <span className="pill info"><span className="dot pulse" /> LIVE TELEMETRY</span>
      </div>
      {error && <div className="banner">Connection hiccup ({error}) — showing the last data received.</div>}
      {!data ? (
        <div className="loading">
          <p className="muted">Connecting to live packet telemetry…</p>
        </div>
      ) : (
        <div className="packet-page-sections">
          <PacketFeed packets={data.packets} />
          <FlowsCard flows={data.flows} />
        </div>
      )}
    </main>
  )
}
