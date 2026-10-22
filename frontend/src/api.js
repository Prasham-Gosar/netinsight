export async function getJSON(url) {
  const res = await fetch(url, { cache: 'no-store' })
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`)
  return res.json()
}

export async function postJSON(url) {
  const res = await fetch(url, { method: 'POST' })
  if (!res.ok) {
    let msg = res.statusText
    try {
      msg = (await res.json()).error || msg
    } catch (e) {
      /* ignore */
    }
    throw new Error(msg)
  }
  return res.json()
}
