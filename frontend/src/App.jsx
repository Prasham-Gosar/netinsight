import React from 'react'
import { usePolling } from './hooks'
import Header from './components/Header'
import HealthCard from './components/HealthCard'
import BandwidthCard from './components/BandwidthCard'
import Kpis from './components/Kpis'
import ProtocolCard from './components/ProtocolCard'
import ApplicationsCard from './components/ApplicationsCard'
import DevicesCard from './components/DevicesCard'
import TimelineCard from './components/TimelineCard'
import AlertsCard from './components/AlertsCard'
import InsightsCard from './components/InsightsCard'
import TopIpsCard from './components/TopIpsCard'
import PacketFeed from './components/PacketFeed'
import FlowsCard from './components/FlowsCard'
import HistoryCard from './components/HistoryCard'
import DemoControls from './components/DemoControls'

export default function App() {
  const { data, error } = usePolling('/api/dashboard', 1000)

  return (
    <div className="page">
      <Header meta={data && data.meta} totals={data && data.totals} error={error && !data ? error : null} />

      {!data ? (
        <div className="loading">
          {error ? (
            <>
              <h2>Can’t reach the NetInsight backend</h2>
              <p className="muted">Make sure <code>python main.py</code> is running, then refresh this page.</p>
            </>
          ) : (
            <p className="muted">Connecting to NetInsight…</p>
          )}
        </div>
      ) : (
        <main>
          {error && <div className="banner">Connection hiccup ({error}) — showing the last data received.</div>}
          {data.meta.mode === 'simulation' && <DemoControls />}

          <div className="grid">
            <div className="span-4">
              <HealthCard health={data.health} />
            </div>
            <div className="span-5">
              <BandwidthCard series={data.bandwidth} rate={data.rate} />
            </div>
            <div className="span-3">
              <Kpis totals={data.totals} />
            </div>

            <div className="span-4">
              <ProtocolCard families={data.protocols} />
            </div>
            <div className="span-4">
              <ApplicationsCard apps={data.applications} />
            </div>
            <div className="span-4">
              <DevicesCard devices={data.devices} />
            </div>

            <div className="span-7">
              <TimelineCard />
            </div>
            <div className="span-5">
              <AlertsCard alerts={data.alerts} baseline={data.baseline} />
            </div>

            <div className="span-5">
              <InsightsCard insights={data.insights} />
            </div>
            <div className="span-7">
              <TopIpsCard ips={data.top_ips} />
            </div>

            <div className="span-12">
              <PacketFeed packets={data.packets} />
            </div>
            <div className="span-12">
              <FlowsCard flows={data.flows} />
            </div>
            <div className="span-12">
              <HistoryCard />
            </div>
          </div>

          <footer className="muted small">
            NetInsight analyses packet <b>metadata only</b> (addresses, ports, sizes, domain names). Payload contents are never stored. Application
            detection is best-effort.
          </footer>
        </main>
      )}
    </div>
  )
}
