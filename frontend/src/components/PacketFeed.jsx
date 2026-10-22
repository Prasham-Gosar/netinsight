import React, { useEffect, useRef, useState } from 'react'
import Card from './Card'
import { FAMILY_COLORS, COLORS, fmtBytes } from '../format'

const MISSING_VALUE = 'Not provided by feed'

function splitEndpoint(endpoint) {
  if (!endpoint) return { address: '–', port: null }
  const match = String(endpoint).match(/^(.*):(\d+)$/)
  return match ? { address: match[1], port: match[2] } : { address: endpoint, port: null }
}

function value(packet, ...keys) {
  for (const key of keys) {
    if (packet[key] !== undefined && packet[key] !== null && packet[key] !== '') return packet[key]
  }
  return MISSING_VALUE
}

function PacketDetails({ packet, onClose }) {
  const source = splitEndpoint(packet.src)
  const destination = splitEndpoint(packet.dst)
  const sourceIp = value(packet, 'src_ip', 'source_ip', 'src')
  const destinationIp = value(packet, 'dst_ip', 'destination_ip', 'dst')
  const ipVersion = value(packet, 'ip_version', 'version', 'src_ip_version')
  const transport = packet.family || (packet.protocol === 'UDP' ? 'UDP' : packet.protocol === 'TCP' ? 'TCP' : packet.protocol)
  const flags = value(packet, 'tcp_flags', 'flags')
  const flagNames = typeof flags === 'string' && flags !== MISSING_VALUE
    ? { S: 'SYN', A: 'ACK', F: 'FIN', R: 'RST', P: 'PSH', U: 'URG', E: 'ECE', C: 'CWR' }
    : null

  useEffect(() => {
    const handleKeyDown = (event) => {
      if (event.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [onClose])

  return (
    <div className="packet-drawer-backdrop" role="presentation" onMouseDown={onClose}>
      <aside className="packet-drawer" role="dialog" aria-modal="true" aria-labelledby="packet-inspector-title" onMouseDown={(event) => event.stopPropagation()}>
        <header className="packet-drawer-head">
          <div>
            <p className="eyebrow">Packet inspection</p>
            <h2 id="packet-inspector-title">Packet #{packet.n}</h2>
            <p className="muted small">{packet.time} · {packet.protocol}</p>
          </div>
          <button className="drawer-close" type="button" aria-label="Close packet inspector" onClick={onClose}>×</button>
        </header>

        <div className="packet-drawer-content">
          <PacketLayer title="Link layer">
            <PacketField label="Source MAC" value={value(packet, 'src_mac', 'source_mac')} />
            <PacketField label="Destination MAC" value={value(packet, 'dst_mac', 'destination_mac')} />
            <PacketField label="EtherType" value={value(packet, 'ethertype', 'ether_type')} />
          </PacketLayer>

          <PacketLayer title="Network layer">
            <PacketField label="Source IP" value={sourceIp === packet.src ? source.address : sourceIp} />
            <PacketField label="Destination IP" value={destinationIp === packet.dst ? destination.address : destinationIp} />
            <PacketField label="TTL / Hop limit" value={value(packet, 'ttl')} />
            <PacketField label="IP version" value={ipVersion === MISSING_VALUE ? inferIpVersion(sourceIp === packet.src ? source.address : sourceIp) : ipVersion} />
            <PacketField label="Header length" value={value(packet, 'header_length', 'ip_header_length')} />
          </PacketLayer>

          <PacketLayer title={`Transport layer · ${transport || 'Unknown'}`}>
            <PacketField label="Source port" value={value(packet, 'src_port') === MISSING_VALUE ? source.port || MISSING_VALUE : packet.src_port} />
            <PacketField label="Destination port" value={value(packet, 'dst_port') === MISSING_VALUE ? destination.port || MISSING_VALUE : packet.dst_port} />
            {transport === 'TCP' ? (
              <>
                <PacketField label="TCP flags" value={flags} />
                <PacketField label="Flags decoded" value={flagNames ? Object.entries(flagNames).filter(([key]) => flags.includes(key)).map(([, name]) => name).join(', ') || 'None' : MISSING_VALUE} />
                <PacketField label="Window size" value={value(packet, 'window', 'window_size')} />
                <PacketField label="Sequence number" value={value(packet, 'seq', 'sequence_number')} />
                <PacketField label="Acknowledgement number" value={value(packet, 'ack', 'ack_number')} />
              </>
            ) : transport === 'UDP' ? (
              <>
                <PacketField label="Datagram length" value={value(packet, 'length', 'udp_length', 'payload_len')} />
                <PacketField label="Checksum" value={value(packet, 'checksum', 'udp_checksum')} />
              </>
            ) : (
              <PacketField label="Transport details" value={MISSING_VALUE} />
            )}
          </PacketLayer>

          <PacketLayer title="Application & metadata">
            <PacketField label="Timestamp" value={value(packet, 'timestamp', 'time')} />
            <PacketField label="Packet size" value={packet.size == null ? MISSING_VALUE : fmtBytes(packet.size)} />
            <PacketField label="Protocol" value={value(packet, 'protocol')} />
            <PacketField label="Application" value={value(packet, 'app')} />
            <PacketField label="Domain" value={value(packet, 'domain')} />
            <div className="packet-explanation">
              <span className="packet-field-label">NetInsight explanation</span>
              <p>{value(packet, 'explanation')}</p>
            </div>
          </PacketLayer>
        </div>
      </aside>
    </div>
  )
}

function PacketLayer({ title, children }) {
  return (
    <section className="packet-layer">
      <h3>{title}</h3>
      <dl>{children}</dl>
    </section>
  )
}

function PacketField({ label, value: fieldValue }) {
  return (
    <div className="packet-field">
      <dt>{label}</dt>
      <dd className={fieldValue === MISSING_VALUE ? 'muted' : ''}>{fieldValue ?? MISSING_VALUE}</dd>
    </div>
  )
}

function inferIpVersion(address) {
  if (address === MISSING_VALUE || address === '–') return MISSING_VALUE
  return String(address).includes(':') ? '6' : '4'
}

export default function PacketFeed({ packets }) {
  const [paused, setPaused] = useState(false)
  const [selectedPacket, setSelectedPacket] = useState(null)
  const frozen = useRef(packets)
  if (!paused) frozen.current = packets
  const rows = frozen.current

  return (
    <Card
      title="Live Packet Feed"
      subtitle="Every packet, translated into plain English"
      right={
        <button className="btn" onClick={() => setPaused(!paused)}>
          {paused ? '▶ Resume' : '⏸ Pause'}
        </button>
      }
    >
      <ul className="feed">
        {rows.slice(0, 14).map((p) => (
          <li key={p.n}>
            <button className="feed-row feed-row-button mono" type="button" onClick={() => setSelectedPacket(p)} aria-label={`Inspect packet ${p.n}`}>
              <span className="muted">#{p.n}</span>
              <span>{p.time}</span>
              <span className="tag" style={{ background: `${FAMILY_COLORS[p.family] || COLORS.gray}26`, color: FAMILY_COLORS[p.family] || COLORS.gray }}>
                {p.protocol}
              </span>
              <span className="ellipsis">
                {p.src} → {p.dst}
              </span>
              <span className="muted">{fmtBytes(p.size)}</span>
              <span className="muted">{p.flags || ''}</span>
              <span className="app">{p.app}</span>
              <span className="feed-inspect" aria-hidden="true">›</span>
            </button>
            <div className="explain">{p.explanation}</div>
          </li>
        ))}
        {rows.length === 0 && <li className="muted small">Waiting for packets…</li>}
      </ul>
      {selectedPacket && <PacketDetails packet={selectedPacket} onClose={() => setSelectedPacket(null)} />}
    </Card>
  )
}
