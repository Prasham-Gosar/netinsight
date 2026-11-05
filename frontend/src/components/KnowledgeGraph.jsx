import React, { useEffect, useMemo, useRef, useState } from 'react'
import ForceGraph3D from 'react-force-graph-3d'
import * as THREE from 'three'
import { getJSON } from '../api'

const COLORS = { gateway: '#36e0ff', device: '#4f9dff', cloud: '#bd6cff', anomalous: '#ff426d' }
const COLOR_VALUES = { gateway: 0x36e0ff, device: 0x4f9dff, cloud: 0xbd6cff, anomalous: 0xff426d }

function nodeAccent(node) {
  return node.status === 'anomalous' ? 'anomalous' : node.type
}

function createNodeObject(node, radius) {
  const accent = nodeAccent(node)
  const color = COLOR_VALUES[accent] || COLOR_VALUES.device
  const group = new THREE.Group()
  group.userData.graphNode = true
  group.userData.anomalous = accent === 'anomalous'
  group.userData.phase = Math.random() * Math.PI * 2

  const core = new THREE.Mesh(
    new THREE.SphereGeometry(radius, 16, 12),
    new THREE.MeshBasicMaterial({ color, transparent: true, opacity: 0.96 })
  )
  core.userData.core = true
  core.userData.anomalous = group.userData.anomalous
  group.add(core)

  const labelCanvas = document.createElement('canvas')
  labelCanvas.width = 512
  labelCanvas.height = 96
  const context = labelCanvas.getContext('2d')
  context.font = '600 30px Segoe UI, sans-serif'
  context.fillStyle = '#e9f2ff'
  context.textAlign = 'center'
  context.fillText(String(node.label || node.id).slice(0, 24), 256, 42)
  const label = new THREE.Sprite(new THREE.SpriteMaterial({
    map: new THREE.CanvasTexture(labelCanvas), transparent: true, depthWrite: false
  }))
  label.scale.set(30, 5.6, 1)
  label.position.y = -radius * 2.2
  group.add(label)
  return group
}

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
  const nodeColor = node => COLORS[nodeAccent(node)] || COLORS.device

  useEffect(() => {
    let frame
    const animate = () => {
      const scene = graphRef.current?.scene()
      if (scene) {
        const time = performance.now() / 520
        scene.traverse(object => {
          if (!object.userData?.graphNode) return
          const pulse = 1 + Math.sin(time + object.userData.phase) * (object.userData.anomalous ? 0.16 : 0.05)
          object.children.forEach(child => {
            if (child.userData.core && child.userData.anomalous) {
              child.scale.setScalar(pulse)
              child.material.opacity = 0.72 + (pulse - 0.84) * 1.2
            }
          })
        })
      }
      frame = requestAnimationFrame(animate)
    }
    frame = requestAnimationFrame(animate)
    return () => cancelAnimationFrame(frame)
  }, [])

  return (
    <main className="graph-page">
      <div className="graph-heading">
        <div><h2>Network Knowledge Graph</h2><p className="muted">Live devices, gateway relationships, and external services. (Click on any node for inside telemetry)</p></div>
        <span className="pill info"><span className="dot pulse" /> LIVE TOPOLOGY</span>
      </div>
      {error && <div className="banner">Graph unavailable ({error})</div>}
      <section className={`graph-card card ${selected ? 'has-inspector' : ''}`}>
        <div className="graph-canvas">
          {graph.nodes.length > 0 && <ForceGraph3D
            ref={graphRef}
            graphData={graph}
            backgroundColor="#0b1020"
            nodeLabel={node => `${node.label}${node.ip ? ` · ${node.ip}` : ''}`}
            nodeVal={nodeSize}
            nodeColor={nodeColor}
            nodeThreeObject={node => createNodeObject(node, nodeSize(node))}
            nodeThreeObjectExtend={false}
            linkColor={link => link.anomalous ? '#ff426d' : '#526b9e'}
            linkWidth={link => link.active ? 1.7 : 0.7}
            linkDirectionalParticles={link => link.active ? 1 : 0}
            linkDirectionalParticleSpeed={link => link.active ? 0.006 : 0}
            linkDirectionalParticleWidth={2}
            linkDirectionalParticleColor={link => link.anomalous ? '#ff426d' : '#4cc9f0'}
            onEngineInitialization={engine => {
              engine.d3Force('charge').strength(-500)
              engine.d3Force('link').distance(125).strength(0.65)
              engine.d3Force('center').strength(0.08)
            }}
            onNodeClick={node => {
              setSelected(node)
              graphRef.current?.cameraPosition({ x: -42, y: 0, z: 205 }, node, 800)
            }}
            warmupTicks={40}
            cooldownTicks={60}
            d3AlphaDecay={0.08}
            d3VelocityDecay={0.45}
            showNavInfo={false}
          />}
          {!graph.nodes.length && !error && <div className="graph-empty muted">Waiting for live network activity…</div>}
        </div>
        <aside className={`graph-inspector graph-glass ${selected ? 'open' : ''}`}>
          {selected ? <><div className="card-head"><div><h2>{selected.label}</h2><p className="muted small">{selected.type}</p></div><button className="link" onClick={() => setSelected(null)}>Close</button></div>
            <div className="inspector-status"><span className={`dot ${selected.status === 'anomalous' ? 'bad' : 'on'}`} /> {selected.status === 'anomalous' ? 'Active anomaly' : 'Normal'}</div>
            <dl className="inspector-details"><dt>IP address</dt><dd>{selected.ip || '—'}</dd><dt>MAC address</dt><dd>{selected.mac || '—'}</dd><dt>Application</dt><dd>{selected.application || selected.domain || '—'}</dd><dt>Traffic volume</dt><dd>{selected.bytes || 0} bytes</dd><dt>Packets</dt><dd>{selected.packets || 0}</dd><dt>Anomalies</dt><dd>{selected.anomalies || 0}</dd></dl>
          </> : <div className="empty muted">Click a node to inspect its telemetry.</div>}
        </aside>
      </section>
    </main>
  )
}
