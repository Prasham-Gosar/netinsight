import React from 'react'

export default function Card({ title, subtitle, right, children, className = '' }) {
  return (
    <section className={`card ${className}`}>
      {(title || right) && (
        <header className="card-head">
          <div>
            <h2>{title}</h2>
            {subtitle && <p className="muted small">{subtitle}</p>}
          </div>
          {right && <div className="card-right">{right}</div>}
        </header>
      )}
      {children}
    </section>
  )
}
