import React from 'react'
import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import App from './App.jsx'
import dashboard from './fixtures/dashboard.json'
import timeline from './fixtures/timeline.json'
import answers from './fixtures/answers.json'

// The fixtures are real responses captured from the running backend (simulation mode).
function mockFetch(handler) {
  globalThis.fetch = vi.fn(async (url) => handler(String(url)))
}
const ok = (body) => ({ ok: true, status: 200, statusText: 'OK', json: async () => body })

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

describe('NetInsight dashboard', () => {
  beforeEach(() => {
    mockFetch((url) => {
      if (url.includes('/api/dashboard')) return ok(dashboard)
      if (url.includes('/api/history/timeline')) return ok(timeline)
      if (url.includes('/api/history/answers')) return ok(answers)
      return { ok: false, status: 404, statusText: 'Not Found', json: async () => ({}) }
    })
  })

  it('renders every section from real backend data', async () => {
    render(<App />)
    expect(await screen.findByText('Network Health')).toBeTruthy()
    for (const title of ['Live Bandwidth', 'Protocol Distribution', 'Top Applications', 'Devices', 'Traffic Timeline',
      'Anomaly Alerts', 'Insights', 'Top Destinations', 'Live Packet Feed', 'Active Flows', 'Ask Your Network']) {
      expect(screen.getAllByText(title).length).toBeGreaterThan(0)
    }
  })

  it('shows detected applications, the health status and the demo controls', async () => {
    render(<App />)
    await screen.findByText('Network Health')
    expect(screen.getAllByText(dashboard.applications[0].name).length).toBeGreaterThan(0)
    expect(screen.getAllByText(dashboard.health.status).length).toBeGreaterThan(0)
    expect(screen.getByText('DNS burst')).toBeTruthy()          // simulation mode only
  })

  it('shows the anomaly alert text and a plain-English packet explanation', async () => {
    render(<App />)
    await screen.findByText('Network Health')
    expect(screen.getAllByText(dashboard.alerts[0].title).length).toBeGreaterThan(0)
    expect(screen.getAllByText(dashboard.alerts[0].message).length).toBeGreaterThan(0)
    expect(screen.getAllByText(dashboard.packets[0].explanation).length).toBeGreaterThan(0)
  })

  it('shows a friendly message when the backend is unreachable', async () => {
    mockFetch(() => {
      throw new Error('network down')
    })
    render(<App />)
    expect(await screen.findByText(/Can’t reach the NetInsight backend/)).toBeTruthy()
  })
})
