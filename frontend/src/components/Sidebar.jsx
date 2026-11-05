import React from 'react'

export default function Sidebar({ page, onNavigate, user, onLogout }) {
  return (
    <aside className="sidebar">
      <div className="sidebar-title">Workspace</div>
      <button className={`nav-item ${page === 'dashboard' ? 'active' : ''}`} onClick={() => onNavigate('dashboard')}>
        <span>▦</span> Dashboard
      </button>
      <button className={`nav-item ${page === 'graph' ? 'active' : ''}`} onClick={() => onNavigate('graph')}>
        <span>⌘</span> Network Knowledge Graph
      </button>
      <button className={`nav-item ${page === 'packets' ? 'active' : ''}`} onClick={() => onNavigate('packets')}>
        <span>≋</span> Packet Feed
      </button>
      <button className={`nav-item ${page === 'reports' ? 'active' : ''}`} onClick={() => onNavigate('reports')}>
        <span>▤</span> My Generated Reports
      </button>
      <div className="sidebar-account">
        <div className="muted small">Signed in as</div>
        <div className="account-name" title={user?.email}>{user?.email}</div>
        <button className="logout-btn" onClick={onLogout}>Log out</button>
      </div>
    </aside>
  )
}
