import { useEffect, useState } from 'react'
import { getJSON } from './api'

// Poll one URL on a timer. Same idea as a live scoreboard refreshing itself.
export function usePolling(url, intervalMs) {
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    let alive = true
    let timer
    const tick = async () => {
      try {
        const json = await getJSON(url)
        if (alive) {
          setData(json)
          setError(null)
        }
      } catch (e) {
        if (alive) setError(String(e.message || e))
      } finally {
        if (alive) timer = setTimeout(tick, intervalMs)
      }
    }
    tick()
    return () => {
      alive = false
      clearTimeout(timer)
    }
  }, [url, intervalMs])

  return { data, error }
}
