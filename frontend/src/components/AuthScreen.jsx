import React, { useState } from 'react'
import { postJSON } from '../api'

export default function AuthScreen({ onAuthenticated, initialError }) {
  const [mode, setMode] = useState('login')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState(initialError || null)
  const [submitting, setSubmitting] = useState(false)

  const submit = async (event) => {
    event.preventDefault()
    const name = username.trim()
    if (!name || !password) {
      setError('Enter both your username and password.')
      return
    }
    if (mode === 'signup' && password.length < 8) {
      setError('Sign up requires a password with at least 8 characters.')
      return
    }
    setSubmitting(true)
    setError(null)
    try {
      const result = await postJSON(`/api/auth/${mode}`, { email: name, password })
      onAuthenticated(result.user)
    } catch (e) {
      setError(e.message || 'Authentication failed. Please try again.')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="auth-page">
      <section className="auth-card">
        <div className="auth-brand">
          <div className="logo">
            <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M2 12h4l3-8 4 16 3-8h6" />
            </svg>
          </div>
          <div><h1>NetInsight</h1><p className="muted small">Network intelligence dashboard</p></div>
        </div>
        <div className="auth-copy">
          <h2>{mode === 'login' ? 'Welcome back' : 'Create your account'}</h2>
          <p className="muted">{mode === 'login' ? 'Sign in to view your network telemetry.' : 'Save reports and insights to your private workspace.'}</p>
        </div>
        <div className="auth-tabs" role="tablist">
          <button className={mode === 'login' ? 'active' : ''} onClick={() => { setMode('login'); setError(null) }} role="tab">Login</button>
          <button className={mode === 'signup' ? 'active' : ''} onClick={() => { setMode('signup'); setError(null) }} role="tab">Sign Up</button>
        </div>
        <form onSubmit={submit}>
          <label>Username<input autoComplete="username" value={username} onChange={e => setUsername(e.target.value)} placeholder="you@example.com" /></label>
          <label>Password<input type="password" autoComplete={mode === 'login' ? 'current-password' : 'new-password'} value={password} onChange={e => setPassword(e.target.value)} placeholder={mode === 'signup' ? 'At least 8 characters' : 'Your password'} /></label>
          {error && <div className="auth-error" role="alert">{error}</div>}
          <button className="auth-submit" type="submit" disabled={submitting}>{submitting ? 'Please wait…' : mode === 'login' ? 'Login to NetInsight' : 'Create account'}</button>
        </form>
      </section>
    </div>
  )
}
