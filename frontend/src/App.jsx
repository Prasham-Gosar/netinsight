import React from 'react'
import { usePolling } from './hooks'
import Header from './components/Header'
import HealthCard from './components/HealthCard'
import BandwidthCard from './components/BandwidthCard'
import Kpis from './components/Kpis'
import ProtocolCard from './components/ProtocolCard'
import ApplicationsCard from './components/ApplicationsCard'
import TimelineCard from './components/TimelineCard'
import AlertsCard from './components/AlertsCard'
import InsightsCard from './components/InsightsCard'
import TopIpsCard from './components/TopIpsCard'
import PacketFeedPage from './components/PacketFeedPage'
import HistoryCard from './components/HistoryCard'
import DemoControls from './components/DemoControls'
import Sidebar from './components/Sidebar'
import ReportsPage from './components/ReportsPage'
import { postJSON } from './api'
import { getJSON } from './api'
import AuthScreen from './components/AuthScreen'
const KnowledgeGraph = React.lazy(() => import('./components/KnowledgeGraph'))

export default function App() {
  const [authState, setAuthState] = React.useState({ loading: true, user: null, error: null })
  const { data, error } = usePolling(authState.user ? '/api/dashboard' : null, 1000)
  const [page, setPage] = React.useState('dashboard')
  const [generating, setGenerating] = React.useState(false)
  const [toast, setToast] = React.useState(null)
  React.useEffect(() => {
    getJSON('/api/auth/session')
      .then(result => setAuthState({ loading: false, user: result.user, error: null }))
      .catch(e => setAuthState({ loading: false, user: null, error: `Can’t reach the NetInsight backend (${e.message || e})` }))
  }, [])
  if (authState.loading) return <div className="auth-loading muted">Loading NetInsight…</div>
  if (!authState.user) return <AuthScreen initialError={authState.error} onAuthenticated={user => setAuthState({ loading: false, user, error: null })} />
  const logout = async () => {
    try { await postJSON('/api/auth/logout') } finally {
      setAuthState({ loading: false, user: null, error: null })
      setPage('dashboard')
    }
  }
  const generate = async () => {
    setGenerating(true)
    try { await postJSON('/api/reports'); setToast('Report generated successfully') }
    catch (e) { setToast(`Could not generate report: ${e.message || e}`) }
    finally { setGenerating(false); setTimeout(() => setToast(null), 3500) }
  }

  return (
    <div className="page">
      <Sidebar page={page} onNavigate={setPage} user={authState.user} onLogout={logout} />
      <div className="content">
      <Header meta={data && data.meta} totals={data && data.totals} error={error && !data ? error : null} onGenerate={generate} generating={generating} />

      {page === 'reports' ? <ReportsPage /> : page === 'packets' ? <PacketFeedPage data={data} error={error} /> : page === 'graph' ? <React.Suspense fallback={<div className="loading"><p className="muted">Loading network graph…</p></div>}><KnowledgeGraph devices={data?.devices} totals={data?.totals} /></React.Suspense> : !data ? (
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
      {toast && <div className={`toast ${toast.startsWith('Could') ? 'error' : ''}`}>{toast}</div>}
    </div>
  )
}
