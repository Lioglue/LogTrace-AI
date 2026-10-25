import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import { EventAnalytics } from '../types';
import {
  LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer,
  BarChart, Bar, Cell, PieChart, Pie,
} from 'recharts';
import { BarChart3 } from 'lucide-react';

const SEVERITY_COLORS: Record<string, string> = {
  low: '#22c55e', medium: '#eab308', high: '#f97316', critical: '#ef4444',
};

export default function AnalyticsPage() {
  const [data, setData] = useState<EventAnalytics | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.analytics.events()
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
    return <div className="text-center py-20 text-dark-400">Failed to load analytics</div>;
  }

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <BarChart3 className="w-6 h-6 text-cyber-blue" />
          Analytics
        </h1>
        <p className="text-dark-400 mt-1">Comprehensive security event analysis</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card">
          <h3 className="text-lg font-semibold text-white mb-4">Events Over Time</h3>
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={data.events_over_time}>
              <XAxis dataKey="date" stroke="#64748b" tick={{ fontSize: 10 }} />
              <YAxis stroke="#64748b" tick={{ fontSize: 11 }} />
              <Tooltip
                contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '8px' }}
                labelStyle={{ color: '#94a3b8' }}
              />
              <Line type="monotone" dataKey="total" stroke="#3b82f6" strokeWidth={2} dot={false} name="Total" />
              <Line type="monotone" dataKey="suspicious" stroke="#ef4444" strokeWidth={2} dot={false} name="Suspicious" />
            </LineChart>
          </ResponsiveContainer>
        </div>

        <div className="card">
          <h3 className="text-lg font-semibold text-white mb-4">Suspicious Events Over Time</h3>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={data.suspicious_over_time}>
              <XAxis dataKey="date" stroke="#64748b" tick={{ fontSize: 10 }} />
              <YAxis stroke="#64748b" tick={{ fontSize: 11 }} />
              <Tooltip
                contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '8px' }}
              />
              <Bar dataKey="count" fill="#ef4444" radius={[2, 2, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="card">
          <h3 className="text-lg font-semibold text-white mb-4">Incidents Over Time</h3>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={data.incidents_over_time}>
              <XAxis dataKey="date" stroke="#64748b" tick={{ fontSize: 10 }} />
              <YAxis stroke="#64748b" tick={{ fontSize: 11 }} />
              <Tooltip
                contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '8px' }}
              />
              <Bar dataKey="count" fill="#8b5cf6" radius={[2, 2, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="card">
          <h3 className="text-lg font-semibold text-white mb-4">Severity Distribution</h3>
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={data.severity_distribution}
                dataKey="count"
                nameKey="severity"
                cx="50%"
                cy="50%"
                outerRadius={100}
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
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="card">
          <h3 className="text-lg font-semibold text-white mb-4">Most Active IP Addresses</h3>
          {data.top_ips.length === 0 ? (
            <p className="text-dark-500 text-sm">No data available</p>
          ) : (
            <div className="space-y-3">
              {data.top_ips.map((item, i) => (
                <div key={item.ip} className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-dark-500 w-4">{i + 1}.</span>
                    <span className="text-dark-200 font-mono text-sm">{item.ip}</span>
                  </div>
                  <span className="text-dark-400 text-sm">{item.count}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="card">
          <h3 className="text-lg font-semibold text-white mb-4">Common Event Types</h3>
          {data.top_event_types.length === 0 ? (
            <p className="text-dark-500 text-sm">No data available</p>
          ) : (
            <div className="space-y-3">
              {data.top_event_types.map((item, i) => (
                <div key={item.type} className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-dark-500 w-4">{i + 1}.</span>
                    <span className="text-dark-200 text-sm">{item.type}</span>
                  </div>
                  <span className="text-dark-400 text-sm">{item.count}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="card">
          <h3 className="text-lg font-semibold text-white mb-4">Most Triggered Rules</h3>
          {data.top_rules.length === 0 ? (
            <p className="text-dark-500 text-sm">No data available</p>
          ) : (
            <div className="space-y-3">
              {data.top_rules.map((item, i) => (
                <div key={item.rule} className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-dark-500 w-4">{i + 1}.</span>
                    <span className="text-dark-200 text-sm">{item.rule}</span>
                  </div>
                  <span className="text-dark-400 text-sm">{item.count}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
