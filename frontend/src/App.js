import React, { useState, useEffect } from "react";
import axios from "axios";
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend,
  AreaChart, Area,
  RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis,
  RadialBarChart, RadialBar,
} from "recharts";
import "./App.css";

const COLORS = ['#ff6b6b', '#ffa36b', '#ffd93d', '#6bcb77', '#4d96ff', '#9b59b6', '#e84393', '#00cec9', '#fd79a8', '#636e72'];
const THREAT_COLORS = {
  'Data Destruction': '#ff4757',
  'Privilege Escalation': '#ff6348',
  'Audit Evasion': '#ffa502',
  'Account Compromise': '#e84393',
  'Reconnaissance': '#5352ed',
  'Other': '#636e72',
};

/* ── Stat Card ─────────────────────────────────────────────── */
function StatCard({ icon, label, value, color, delay }) {
  return (
    <div className="stat-card" style={{ animationDelay: `${delay}ms`, '--accent': color }}>
      <div className="stat-icon">{icon}</div>
      <div className="stat-value" style={{ color }}>{value}</div>
      <div className="stat-label">{label}</div>
    </div>
  );
}

/* ── Threat Badge ──────────────────────────────────────────── */
function ThreatBadge({ category }) {
  const colorMap = {
    'Data Destruction': '#ff4757',
    'Privilege Escalation': '#ff6348',
    'Audit Evasion': '#ffa502',
    'Account Compromise': '#e84393',
    'Reconnaissance': '#5352ed',
  };
  const bg = colorMap[category] || '#636e72';
  return <span className="threat-badge" style={{ background: bg }}>{category}</span>;
}

/* ── Risk Level Badge ──────────────────────────────────────── */
function RiskBadge({ score }) {
  let cls = 'risk-badge ';
  if (score >= 8) cls += 'critical';
  else if (score >= 7) cls += 'high';
  else cls += 'medium';
  return <span className={cls}>{score}</span>;
}

/* ── Custom Tooltip for charts ─────────────────────────────── */
const CustomTooltip = ({ active, payload, label }) => {
  if (active && payload && payload.length) {
    return (
      <div className="custom-tooltip">
        <p className="tooltip-label">{label}</p>
        {payload.map((entry, i) => (
          <p key={i} style={{ color: entry.color }}>
            {entry.name}: <strong>{typeof entry.value === 'number' ? entry.value.toFixed(2) : entry.value}</strong>
          </p>
        ))}
      </div>
    );
  }
  return null;
};

/* ── Main App ──────────────────────────────────────────────── */
function App() {
  const [data, setData] = useState([]);
  const [analytics, setAnalytics] = useState(null);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState("overview");
  const [page, setPage] = useState(1);
  const rowsPerPage = 8;

  const fetchAll = async () => {
    setLoading(true);
    try {
      const apiUrl = process.env.REACT_APP_API_URL || "http://127.0.0.1:5000";
      const [susRes, anaRes] = await Promise.all([
        axios.get(`${apiUrl}/api/suspicious`),
        axios.get(`${apiUrl}/api/analytics`),
      ]);
      setData(susRes.data);
      setAnalytics(anaRes.data);
      setPage(1);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  /* auto-fetch on mount */
  useEffect(() => { fetchAll(); }, []);

  const startIndex = (page - 1) * rowsPerPage;
  const selectedData = data.slice(startIndex, startIndex + rowsPerPage);
  const totalPages = Math.ceil(data.length / rowsPerPage);

  /* ---- helpers for threat category from reason ---- */
  const getCategory = (reason) => {
    if (!reason) return 'Other';
    const r = reason.toLowerCase();
    if (r.includes('data destruction')) return 'Data Destruction';
    if (r.includes('privilege escalation')) return 'Privilege Escalation';
    if (r.includes('audit evasion')) return 'Audit Evasion';
    if (r.includes('compromise')) return 'Account Compromise';
    if (r.includes('reconnaissance')) return 'Reconnaissance';
    return 'Other';
  };

  /* ─── RENDER ──────────────────────────────────── */
  return (
    <div className="app">
      {/* ── Header ── */}
      <header className="header">
        <div className="header-inner">
          <div className="brand">
            <span className="brand-icon">🛡️</span>
            <div>
              <h1>Cloud Anomaly Detection</h1>
              <p className="subtitle">AI-Powered Suspicious Activity Analysis</p>
            </div>
          </div>
          <button
            className={`scan-btn ${loading ? 'scanning' : ''}`}
            onClick={fetchAll}
            disabled={loading}
          >
            {loading ? (
              <><span className="spinner"></span> Scanning...</>
            ) : (
              <><span className="scan-icon">⟳</span> Re-Scan</>
            )}
          </button>
        </div>
      </header>

      {/* ── Loading State ── */}
      {loading && !analytics && (
        <div className="loading-screen">
          <div className="pulse-ring"></div>
          <p>Analyzing cloud logs for anomalies...</p>
        </div>
      )}

      {analytics && (
        <>
          {/* ── Stats Row ── */}
          <section className="stats-row">
            <StatCard icon="🚨" label="Suspicious Events" value={analytics.summary.total_suspicious} color="#ff4757" delay={0} />
            <StatCard icon="⚠️" label="Critical Threats" value={analytics.summary.critical_events} color="#e84393" delay={80} />
            <StatCard icon="🔥" label="High Risk" value={analytics.summary.high_events} color="#ff6348" delay={160} />
            <StatCard icon="📊" label="Avg Risk Score" value={analytics.summary.avg_risk_score} color="#ffa502" delay={240} />
            <StatCard icon="👤" label="Unique Users" value={analytics.summary.unique_users} color="#5352ed" delay={320} />
            <StatCard icon="🌐" label="Unique IPs" value={analytics.summary.unique_ips} color="#00cec9" delay={400} />
          </section>

          {/* ── Tab Navigation ── */}
          <nav className="tab-nav">
            {[
              { id: 'overview', label: '📈 Overview', },
              { id: 'threats', label: '🎯 Threat Analysis', },
              { id: 'timeline', label: '📅 Timeline', },
              { id: 'events', label: '📋 Event Log', },
            ].map(tab => (
              <button
                key={tab.id}
                className={`tab-btn ${activeTab === tab.id ? 'active' : ''}`}
                onClick={() => setActiveTab(tab.id)}
              >
                {tab.label}
              </button>
            ))}
          </nav>

          {/* ══════════ OVERVIEW TAB ══════════ */}
          {activeTab === 'overview' && (
            <section className="dashboard-grid">
              {/* Risk Score Distribution */}
              <div className="card card-wide">
                <h3 className="card-title">
                  <span className="card-icon">📊</span>
                  Risk Score Distribution
                </h3>
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart data={analytics.risk_distribution} barSize={48}>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                    <XAxis dataKey="range" tick={{ fill: '#a0aec0', fontSize: 12 }} />
                    <YAxis tick={{ fill: '#a0aec0', fontSize: 12 }} />
                    <Tooltip content={<CustomTooltip />} />
                    <Bar dataKey="count" name="Events" radius={[8, 8, 0, 0]}>
                      {analytics.risk_distribution.map((_, i) => (
                        <Cell key={i} fill={COLORS[i % COLORS.length]} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>

              {/* Event Types Pie */}
              <div className="card">
                <h3 className="card-title">
                  <span className="card-icon">🧩</span>
                  Event Types Breakdown
                </h3>
                <ResponsiveContainer width="100%" height={300}>
                  <PieChart>
                    <Pie
                      data={analytics.events_by_type}
                      cx="50%" cy="50%"
                      innerRadius={55}
                      outerRadius={100}
                      paddingAngle={3}
                      dataKey="value"
                      label={({ name, percent }) => `${name} (${(percent * 100).toFixed(0)}%)`}
                      labelLine={{ stroke: 'rgba(255,255,255,0.3)' }}
                    >
                      {analytics.events_by_type.map((_, i) => (
                        <Cell key={i} fill={COLORS[i % COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip content={<CustomTooltip />} />
                  </PieChart>
                </ResponsiveContainer>
              </div>

              {/* Threat Breakdown */}
              <div className="card">
                <h3 className="card-title">
                  <span className="card-icon">🎯</span>
                  Threat Categories
                </h3>
                <ResponsiveContainer width="100%" height={300}>
                  <PieChart>
                    <Pie
                      data={analytics.threat_breakdown}
                      cx="50%" cy="50%"
                      outerRadius={100}
                      dataKey="count"
                      nameKey="category"
                      label={({ category, percent }) => `${category} ${(percent * 100).toFixed(0)}%`}
                      labelLine={{ stroke: 'rgba(255,255,255,0.3)' }}
                    >
                      {analytics.threat_breakdown.map((entry, i) => (
                        <Cell key={i} fill={THREAT_COLORS[entry.category] || COLORS[i]} />
                      ))}
                    </Pie>
                    <Tooltip content={<CustomTooltip />} />
                  </PieChart>
                </ResponsiveContainer>
              </div>

              {/* Hourly Activity Heatmap */}
              <div className="card card-wide">
                <h3 className="card-title">
                  <span className="card-icon">🕐</span>
                  Hourly Activity Pattern
                </h3>
                <ResponsiveContainer width="100%" height={280}>
                  <AreaChart data={analytics.hourly_activity}>
                    <defs>
                      <linearGradient id="hourGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#ff6b6b" stopOpacity={0.6} />
                        <stop offset="95%" stopColor="#ff6b6b" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                    <XAxis
                      dataKey="hour"
                      tick={{ fill: '#a0aec0', fontSize: 11 }}
                      tickFormatter={(h) => `${String(h).padStart(2, '0')}:00`}
                    />
                    <YAxis tick={{ fill: '#a0aec0', fontSize: 11 }} />
                    <Tooltip content={<CustomTooltip />} />
                    <Area
                      type="monotone" dataKey="count" name="Events"
                      stroke="#ff6b6b" fill="url(#hourGrad)" strokeWidth={2}
                    />
                  </AreaChart>
                </ResponsiveContainer>
                <div className="hour-legend">
                  <span className="night-indicator">🌙 Night (00-06) — Off-hours, higher suspicion</span>
                </div>
              </div>
            </section>
          )}

          {/* ══════════ THREAT ANALYSIS TAB ══════════ */}
          {activeTab === 'threats' && (
            <section className="dashboard-grid">
              {/* User Risk Radar */}
              <div className="card">
                <h3 className="card-title">
                  <span className="card-icon">👤</span>
                  User Risk Profile
                </h3>
                <ResponsiveContainer width="100%" height={320}>
                  <RadarChart outerRadius={100} data={analytics.user_analysis.map(u => ({
                    user: u.user,
                    events: u.total_events,
                    avgRisk: u.avg_risk,
                    maxRisk: u.max_risk,
                  }))}>
                    <PolarGrid stroke="rgba(255,255,255,0.1)" />
                    <PolarAngleAxis dataKey="user" tick={{ fill: '#a0aec0', fontSize: 11 }} />
                    <PolarRadiusAxis tick={{ fill: '#a0aec0', fontSize: 10 }} />
                    <Radar name="Total Events" dataKey="events" stroke="#ff6b6b" fill="#ff6b6b" fillOpacity={0.3} />
                    <Radar name="Avg Risk" dataKey="avgRisk" stroke="#ffa502" fill="#ffa502" fillOpacity={0.2} />
                    <Legend wrapperStyle={{ color: '#a0aec0', fontSize: 12 }} />
                    <Tooltip content={<CustomTooltip />} />
                  </RadarChart>
                </ResponsiveContainer>
              </div>

              {/* IP Address Analysis */}
              <div className="card">
                <h3 className="card-title">
                  <span className="card-icon">🌐</span>
                  Source IP Analysis
                </h3>
                <ResponsiveContainer width="100%" height={320}>
                  <RadialBarChart
                    innerRadius="20%" outerRadius="90%"
                    data={analytics.ip_analysis.map((ip, i) => ({
                      ...ip,
                      fill: COLORS[i % COLORS.length],
                      name: `IP: ${ip.ip}`,
                    }))}
                    startAngle={180} endAngle={0}
                  >
                    <RadialBar
                      label={{ position: 'insideStart', fill: '#fff', fontSize: 11 }}
                      background={{ fill: 'rgba(255,255,255,0.05)' }}
                      dataKey="count"
                    />
                    <Legend wrapperStyle={{ color: '#a0aec0', fontSize: 11 }} />
                    <Tooltip content={<CustomTooltip />} />
                  </RadialBarChart>
                </ResponsiveContainer>
              </div>

              {/* Threat Category Cards */}
              <div className="card card-wide">
                <h3 className="card-title">
                  <span className="card-icon">⚡</span>
                  Threat Intelligence Breakdown
                </h3>
                <div className="threat-grid">
                  {analytics.threat_breakdown.map((threat, i) => (
                    <div
                      key={i}
                      className="threat-card"
                      style={{ borderColor: THREAT_COLORS[threat.category] || '#636e72' }}
                    >
                      <div className="threat-card-count" style={{ color: THREAT_COLORS[threat.category] || '#636e72' }}>
                        {threat.count}
                      </div>
                      <div className="threat-card-label">{threat.category}</div>
                      <div className="threat-card-bar">
                        <div
                          className="threat-card-fill"
                          style={{
                            width: `${(threat.count / analytics.summary.total_suspicious) * 100}%`,
                            background: THREAT_COLORS[threat.category] || '#636e72',
                          }}
                        ></div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* User Table */}
              <div className="card card-wide">
                <h3 className="card-title">
                  <span className="card-icon">🔍</span>
                  User Activity Summary
                </h3>
                <div className="table-wrapper">
                  <table className="analysis-table">
                    <thead>
                      <tr>
                        <th>User</th>
                        <th>Total Events</th>
                        <th>Avg Risk Score</th>
                        <th>Max Risk Score</th>
                        <th>Threat Level</th>
                      </tr>
                    </thead>
                    <tbody>
                      {analytics.user_analysis.map((user, i) => (
                        <tr key={i}>
                          <td className="user-cell">
                            <span className="user-avatar">{user.user[0]?.toUpperCase()}</span>
                            {user.user}
                          </td>
                          <td><span className="count-pill">{user.total_events}</span></td>
                          <td><RiskBadge score={user.avg_risk} /></td>
                          <td><RiskBadge score={user.max_risk} /></td>
                          <td>
                            <span className={`level-badge ${user.max_risk >= 8 ? 'critical' : user.max_risk >= 7 ? 'high' : 'medium'}`}>
                              {user.max_risk >= 8 ? '🔴 CRITICAL' : user.max_risk >= 7 ? '🟠 HIGH' : '🟡 MEDIUM'}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </section>
          )}

          {/* ══════════ TIMELINE TAB ══════════ */}
          {activeTab === 'timeline' && (
            <section className="dashboard-grid">
              <div className="card card-full">
                <h3 className="card-title">
                  <span className="card-icon">📅</span>
                  Suspicious Activity Timeline
                </h3>
                <ResponsiveContainer width="100%" height={400}>
                  <AreaChart data={analytics.timeline}>
                    <defs>
                      <linearGradient id="countGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#5352ed" stopOpacity={0.5} />
                        <stop offset="95%" stopColor="#5352ed" stopOpacity={0} />
                      </linearGradient>
                      <linearGradient id="riskGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#ff4757" stopOpacity={0.5} />
                        <stop offset="95%" stopColor="#ff4757" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                    <XAxis dataKey="date" tick={{ fill: '#a0aec0', fontSize: 11 }} angle={-30} textAnchor="end" height={60} />
                    <YAxis yAxisId="left" tick={{ fill: '#a0aec0', fontSize: 11 }} />
                    <YAxis yAxisId="right" orientation="right" tick={{ fill: '#a0aec0', fontSize: 11 }} />
                    <Tooltip content={<CustomTooltip />} />
                    <Legend wrapperStyle={{ color: '#a0aec0', fontSize: 12 }} />
                    <Area yAxisId="left" type="monotone" dataKey="count" name="Event Count" stroke="#5352ed" fill="url(#countGrad)" strokeWidth={2} />
                    <Area yAxisId="right" type="monotone" dataKey="avg_risk" name="Avg Risk Score" stroke="#ff4757" fill="url(#riskGrad)" strokeWidth={2} />
                  </AreaChart>
                </ResponsiveContainer>
              </div>

              {/* Date range info */}
              <div className="card card-full">
                <h3 className="card-title">
                  <span className="card-icon">📆</span>
                  Analysis Period
                </h3>
                <div className="period-info">
                  <div className="period-block">
                    <span className="period-label">Start</span>
                    <span className="period-value">{analytics.summary.date_range_start?.split(' ')[0]}</span>
                  </div>
                  <div className="period-arrow">→</div>
                  <div className="period-block">
                    <span className="period-label">End</span>
                    <span className="period-value">{analytics.summary.date_range_end?.split(' ')[0]}</span>
                  </div>
                  <div className="period-block highlight">
                    <span className="period-label">Total Alerts</span>
                    <span className="period-value">{analytics.summary.total_suspicious}</span>
                  </div>
                  <div className="period-block highlight">
                    <span className="period-label">Event Types</span>
                    <span className="period-value">{analytics.summary.unique_event_types}</span>
                  </div>
                </div>
              </div>
            </section>
          )}

          {/* ══════════ EVENT LOG TAB ══════════ */}
          {activeTab === 'events' && (
            <section className="dashboard-grid">
              <div className="card card-full">
                <h3 className="card-title">
                  <span className="card-icon">📋</span>
                  Suspicious Activity Log
                  <span className="event-count-badge">{data.length} events</span>
                </h3>
                <div className="table-wrapper">
                  <table className="event-table">
                    <thead>
                      <tr>
                        <th>Timestamp</th>
                        <th>Event</th>
                        <th>User</th>
                        <th>Source IP</th>
                        <th>Risk</th>
                        <th>Threat Category</th>
                        <th>Reason</th>
                      </tr>
                    </thead>
                    <tbody>
                      {selectedData.map((item, i) => (
                        <tr key={i} className="event-row">
                          <td className="mono-cell">{item.eventTime?.split('+')[0]}</td>
                          <td>
                            <span className="event-name">{item.eventName_raw}</span>
                          </td>
                          <td>
                            <span className="user-cell">
                              <span className="user-avatar">{(item.userIdentityuserName || 'U')[0].toUpperCase()}</span>
                              {item.userIdentityuserName || 'Unknown'}
                            </span>
                          </td>
                          <td className="mono-cell">{item.sourceIPAddress}</td>
                          <td><RiskBadge score={item.risk_score} /></td>
                          <td><ThreatBadge category={getCategory(item.reason)} /></td>
                          <td className="reason-cell">{item.reason}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                {/* Pagination */}
                <div className="pagination">
                  <button onClick={() => setPage(1)} disabled={page === 1}>⟪</button>
                  <button onClick={() => setPage(p => p - 1)} disabled={page === 1}>← Prev</button>
                  <span className="page-info">Page {page} of {totalPages}</span>
                  <button onClick={() => setPage(p => p + 1)} disabled={page === totalPages}>Next →</button>
                  <button onClick={() => setPage(totalPages)} disabled={page === totalPages}>⟫</button>
                </div>
              </div>
            </section>
          )}
        </>
      )}
    </div>
  );
}

export default App;