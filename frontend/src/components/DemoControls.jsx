import React, { useState } from 'react'
import { postJSON } from '../api'

const ACTIONS = [
  ['dns_burst', 'DNS burst', 'A burst of DNS lookups (~10× normal)'],
  ['degradation', 'Bad network', 'High latency, packet loss, failed connections'],
  ['bandwidth_spike', 'Big download', 'A large download saturating the link'],
  ['scan', 'Port scan', 'One host probing many addresses'],
]

export default function DemoControls() {
  const [msg, setMsg] = useState('')
  const fire = async (kind) => {
    try {
      const r = await postJSON(`/api/demo/${kind}`)
      setMsg(`Injected “${kind}” for ${r.duration}s — watch health & alerts`)
    } catch (e) {
      setMsg(`Could not inject: ${e.message}`)
    }
  }
  return (
    <div className="demo">
      <span className="muted small">Demo — inject a problem:</span>
      {ACTIONS.map(([k, label, tip]) => (
        <button key={k} className="btn" title={tip} onClick={() => fire(k)}>
          {label}
        </button>
      ))}
      {msg && <span className="small demo-msg">{msg}</span>}
    </div>
  )
}
