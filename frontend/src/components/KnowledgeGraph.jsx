import React, { useEffect, useMemo, useRef, useState } from 'react'
import ForceGraph3D from 'react-force-graph-3d'
import { getJSON } from '../api'

const COLORS = { gateway: '#4cc9f0', device: '#3ddc97', cloud: '#b388ff', anomalous: '#ff5c7a' }

export default function KnowledgeGraph() {
  const [graph, setGraph] = useState({ nodes: [], links: [] })
  const [selected, setSelected] = useState(null)
  const [error, setError] = useState(null)
  const graphRef = useRef()

  useEffect(() => {
    let active = true
    const load = () => getJSON('/api/graph/topology')
      .then(data => { if (active) { setGraph(data); setError(null) } })
      .catch(e => { if (active) setError(e.message || String(e)) })
    load()
    const timer = setInterval(load, 5000)
    return () => { active = false; clearInterval(timer) }
  }, [])

  const maxBytes = useMemo(() => Math.max(1, ...graph.nodes.map(node => node.bytes || 0)), [graph.nodes])
  const nodeSize = node => 4 + 12 * Math.sqrt((node.bytes || 0) / maxBytes)
  const nodeColor = node => node.status === 'anomalous' ? COLORS.anomalous : COLORS[node.type] || COLORS.device

  return (
    <main className="graph-page">
      <div className="graph-heading">
        <div><h2>Network Knowledge Graph</h2><p className="muted">Live devices, gateway relationships, and external services.</p></div>
        <span className="pill info"><span className="dot pulse" /> LIVE TOPOLOGY</span>
      </div>
      {error && <div className="banner">Graph unavailable ({error})</div>}
      <section className="graph-card card">
        <div className="graph-canvas">
          {graph.nodes.length > 0 && <ForceGraph3D
            ref={graphRef}
            graphData={graph}
            backgroundColor="#0b1020"
            nodeLabel={node => `${node.label}${node.ip ? ` · ${node.ip}` : ''}`}
            nodeVal={nodeSize}
            nodeColor={nodeColor}
            linkColor={link => link.anomalous ? '#ff5c7a' : '#42527f'}
            linkWidth={link => link.active ? 1.8 : 0.8}
            linkDirectionalParticles={link => link.active ? 2 : 0}
            linkDirectionalParticleSpeed={link => link.active ? 0.008 : 0}
            linkDirectionalParticleWidth={1.6}
            onNodeClick={node => { setSelected(node); graphRef.current?.cameraPosition({ x: 0, y: 0, z: 180 }, node, 700) }}
            cooldownTicks={80}
            d3AlphaDecay={0.04}
            d3VelocityDecay={0.3}
            showNavInfo={false}
          />}
          {!graph.nodes.length && !error && <div className="graph-empty muted">Waiting for live network activity…</div>}
        </div>
        <aside className={`graph-inspector ${selected ? 'open' : ''}`}>
          {selected ? <><div className="card-head"><div><h2>{selected.label}</h2><p className="muted small">{selected.type}</p></div><button className="link" onClick={() => setSelected(null)}>Close</button></div>
            <div className="inspector-status"><span className={`dot ${selected.status === 'anomalous' ? 'bad' : 'on'}`} /> {selected.status === 'anomalous' ? 'Active anomaly' : 'Normal'}</div>
            <dl className="inspector-details"><dt>IP address</dt><dd>{selected.ip || '—'}</dd><dt>MAC address</dt><dd>{selected.mac || '—'}</dd><dt>Application</dt><dd>{selected.application || selected.domain || '—'}</dd><dt>Traffic volume</dt><dd>{selected.bytes || 0} bytes</dd><dt>Packets</dt><dd>{selected.packets || 0}</dd><dt>Anomalies</dt><dd>{selected.anomalies || 0}</dd></dl>
          </> : <div className="empty muted">Click a node to inspect its telemetry.</div>}
        </aside>
      </section>
    </main>
  )
}
