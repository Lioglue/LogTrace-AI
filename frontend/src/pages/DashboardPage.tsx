import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../services/api';
import { DashboardAnalytics } from '../types';
import { getSeverityColor, getRiskColor, getRiskLabel, formatDate } from '../utils';
import {
  Database, AlertTriangle, Shield, FileWarning,
  ArrowRight, Upload,
} from 'lucide-react';
import {
  LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, BarChart, Bar,
} from 'recharts';

const SEVERITY_COLORS: Record<string, string> = {
  low: '#22c55e',
  medium: '#eab308',
  high: '#f97316',
  critical: '#ef4444',
};

const RISK_COLORS = ['#22c55e', '#eab308', '#f97316', '#ef4444'];

export default function DashboardPage() {
  const [data, setData] = useState<DashboardAnalytics | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.analytics.dashboard()
      .then(setData)
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="w-8 h-8 border-2 border-cyber-blue border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  if (!data) {
    return (
      <div className="text-center py-20">
        <p className="text-dark-400">Failed to load dashboard data</p>
      </div>
    );
  }

  const statCards = [
    { label: 'Total Logs Analyzed', value: data.total_logs, icon: Database, color: 'text-cyber-blue' },
    { label: 'Suspicious Events', value: data.suspicious_events, icon: AlertTriangle, color: 'text-cyber-yellow' },
    { label: 'Active Incidents', value: data.active_incidents, icon: Shield, color: 'text-cyber-cyan' },
    { label: 'Critical Incidents', value: data.critical_incidents, icon: FileWarning, color: 'text-cyber-red' },
  ];

  return (
    <div className="space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Dashboard</h1>
          <p className="text-dark-400 mt-1">Security overview and recent activity</p>
        </div>
        <Link to="/upload" className="btn-primary flex items-center gap-2">
          <Upload className="w-4 h-4" /> Upload Logs
        </Link>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {statCards.map((card) => (
          <div key={card.label} className="card flex items-center gap-4">
            <div className={`w-12 h-12 rounded-lg bg-dark-700 flex items-center justify-center ${card.color}`}>
              <card.icon className="w-6 h-6" />
            </div>
            <div>
              <p className="text-sm text-dark-400">{card.label}</p>
              <p className="text-2xl font-bold text-white">{card.value}</p>
            </div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card">
          <h3 className="text-lg font-semibold text-white mb-4">Events Over Time</h3>
          <ResponsiveContainer width="100%" height={250}>
            <LineChart data={data.events_over_time}>
              <XAxis dataKey="date" stroke="#64748b" tick={{ fontSize: 11 }} />
              <YAxis stroke="#64748b" tick={{ fontSize: 11 }} />
              <Tooltip
                contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '8px' }}
                labelStyle={{ color: '#94a3b8' }}
              />
              <Line type="monotone" dataKey="count" stroke="#3b82f6" strokeWidth={2} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>

        <div className="card">
          <h3 className="text-lg font-semibold text-white mb-4">Severity Distribution</h3>
          <ResponsiveContainer width="100%" height={250}>
            <PieChart>
              <Pie
                data={data.severity_distribution}
                dataKey="count"
                nameKey="severity"
                cx="50%"
                cy="50%"
                outerRadius={90}
                label={({ severity, count }) => `${severity}: ${count}`}
              >
                {data.severity_distribution.map((entry) => (
                  <Cell key={entry.severity} fill={SEVERITY_COLORS[entry.severity] || '#64748b'} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>

        <div className="card">
          <h3 className="text-lg font-semibold text-white mb-4">Incidents by Risk Level</h3>
          <ResponsiveContainer width="100%" height={250}>
            <BarChart data={data.incidents_by_risk}>
              <XAxis dataKey="level" stroke="#64748b" tick={{ fontSize: 12 }} />
              <YAxis stroke="#64748b" tick={{ fontSize: 11 }} />
              <Tooltip
                contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '8px' }}
              />
              <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                {data.incidents_by_risk.map((_, index) => (
                  <Cell key={index} fill={RISK_COLORS[index]} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="card">
          <h3 className="text-lg font-semibold text-white mb-4">Quick Actions</h3>
          <div className="space-y-3">
            <Link to="/upload" className="flex items-center justify-between p-3 bg-dark-700 rounded-lg hover:bg-dark-600 transition-colors">
              <div className="flex items-center gap-3">
                <Upload className="w-5 h-5 text-cyber-blue" />
                <span className="text-dark-200">Upload New Logs</span>
              </div>
              <ArrowRight className="w-4 h-4 text-dark-400" />
            </Link>
            <Link to="/explorer" className="flex items-center justify-between p-3 bg-dark-700 rounded-lg hover:bg-dark-600 transition-colors">
              <div className="flex items-center gap-3">
                <Database className="w-5 h-5 text-cyber-cyan" />
                <span className="text-dark-200">Explore Events</span>
              </div>
              <ArrowRight className="w-4 h-4 text-dark-400" />
            </Link>
            <Link to="/incidents" className="flex items-center justify-between p-3 bg-dark-700 rounded-lg hover:bg-dark-600 transition-colors">
              <div className="flex items-center gap-3">
                <AlertTriangle className="w-5 h-5 text-cyber-yellow" />
                <span className="text-dark-200">View Incidents</span>
              </div>
              <ArrowRight className="w-4 h-4 text-dark-400" />
            </Link>
            <button
              onClick={async () => {
                try {
                  await api.demo.load();
                  window.location.reload();
                } catch (e) { console.error(e); }
              }}
              className="flex items-center justify-between w-full p-3 bg-dark-700 rounded-lg hover:bg-dark-600 transition-colors"
            >
              <div className="flex items-center gap-3">
                <Shield className="w-5 h-5 text-cyber-green" />
                <span className="text-dark-200">Load Demo Data</span>
              </div>
              <ArrowRight className="w-4 h-4 text-dark-400" />
            </button>
          </div>
        </div>
      </div>

      {data.recent_incidents.length > 0 && (
        <div className="card">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-white">Recent Incidents</h3>
            <Link to="/incidents" className="text-sm text-cyber-blue hover:text-blue-400">View All</Link>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-dark-400 border-b border-dark-700">
                  <th className="text-left py-3 px-4">ID</th>
                  <th className="text-left py-3 px-4">Title</th>
                  <th className="text-left py-3 px-4">Severity</th>
                  <th className="text-left py-3 px-4">Risk Score</th>
                  <th className="text-left py-3 px-4">Confidence</th>
                  <th className="text-left py-3 px-4">Status</th>
                  <th className="text-left py-3 px-4">Created</th>
                </tr>
              </thead>
              <tbody>
                {data.recent_incidents.map((inc: any) => (
                  <tr key={inc.id} className="border-b border-dark-700/50 hover:bg-dark-700/30">
                    <td className="py-3 px-4 text-dark-200">#{inc.id}</td>
                    <td className="py-3 px-4 text-white">
                      <Link to={`/incidents/${inc.id}`} className="hover:text-cyber-blue">{inc.title}</Link>
                    </td>
                    <td className="py-3 px-4">
                      <span className={getSeverityColor(inc.severity) + ' px-2 py-1 rounded-full text-xs font-medium'}>
                        {inc.severity?.toUpperCase()}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      <div className="flex items-center gap-2">
                        <div className="w-16 h-2 bg-dark-600 rounded-full overflow-hidden">
                          <div className="h-full rounded-full" style={{ width: `${inc.risk_score}%`, backgroundColor: getRiskColor(inc.risk_score) }} />
                        </div>
                        <span className="text-dark-200">{inc.risk_score}</span>
                      </div>
                    </td>
                    <td className="py-3 px-4 text-dark-200">{inc.confidence}%</td>
                    <td className="py-3 px-4">
                      <span className="text-xs font-medium text-dark-300 bg-dark-600 px-2 py-1 rounded-full">{inc.status}</span>
                    </td>
                    <td className="py-3 px-4 text-dark-400">{formatDate(inc.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {data.recent_suspicious.length > 0 && (
        <div className="card">
          <h3 className="text-lg font-semibold text-white mb-4">Recent Suspicious Events</h3>
          <div className="space-y-3">
            {data.recent_suspicious.map((evt: any) => (
              <div key={evt.id} className="flex items-center gap-4 p-3 bg-dark-700 rounded-lg">
                <span className={getSeverityColor(evt.severity) + ' px-2 py-1 rounded-full text-xs font-medium'}>
                  {evt.severity?.toUpperCase()}
                </span>
                <span className="text-white font-medium">{evt.event_type}</span>
                {evt.ip_address && <span className="text-dark-400 text-sm">{evt.ip_address}</span>}
                {evt.username && <span className="text-dark-400 text-sm">user: {evt.username}</span>}
                <span className="text-dark-500 text-sm ml-auto">{formatDate(evt.timestamp)}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
