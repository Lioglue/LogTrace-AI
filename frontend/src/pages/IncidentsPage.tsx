import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../services/api';
import { Incident } from '../types';
import { getSeverityColor, getRiskColor, formatDate } from '../utils';
import { Search, Filter, ChevronLeft, ChevronRight, X } from 'lucide-react';

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(0);
  const [filters, setFilters] = useState({ severity: '', status: '' });
  const limit = 20;

  useEffect(() => {
    setLoading(true);
    const params: Record<string, string> = {};
    if (filters.severity) params.severity = filters.severity;
    if (filters.status) params.status = filters.status;
    api.incidents.list(params)
      .then(setIncidents)
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [filters]);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Incidents</h1>
        <p className="text-dark-400 mt-1">Potential security incidents requiring investigation</p>
      </div>

      <div className="card">
        <div className="flex items-center gap-3 mb-4">
          <select
            value={filters.severity}
            onChange={(e) => setFilters({ ...filters, severity: e.target.value })}
            className="input-field"
          >
            <option value="">All Severities</option>
            <option value="low">Low</option>
            <option value="medium">Medium</option>
            <option value="high">High</option>
            <option value="critical">Critical</option>
          </select>
          <select
            value={filters.status}
            onChange={(e) => setFilters({ ...filters, status: e.target.value })}
            className="input-field"
          >
            <option value="">All Statuses</option>
            <option value="open">Open</option>
            <option value="investigating">Investigating</option>
            <option value="resolved">Resolved</option>
            <option value="closed">Closed</option>
          </select>
        </div>
      </div>

      <div className="card">
        {loading ? (
          <div className="flex items-center justify-center h-32">
            <div className="w-8 h-8 border-2 border-cyber-blue border-t-transparent rounded-full animate-spin" />
          </div>
        ) : incidents.length === 0 ? (
          <div className="text-center py-16">
            <p className="text-dark-400 text-lg">No incidents found</p>
            <p className="text-dark-500 text-sm mt-2">Upload some logs to get started</p>
          </div>
        ) : (
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
                  <th className="text-left py-3 px-4">Events</th>
                  <th className="text-left py-3 px-4">Created</th>
                </tr>
              </thead>
              <tbody>
                {incidents.map((inc) => (
                  <tr key={inc.id} className="border-b border-dark-700/50 hover:bg-dark-700/30">
                    <td className="py-3 px-4 text-dark-300">#{inc.id}</td>
                    <td className="py-3 px-4">
                      <Link to={`/incidents/${inc.id}`} className="text-white hover:text-cyber-blue font-medium">
                        {inc.title}
                      </Link>
                      <p className="text-dark-400 text-xs mt-0.5">
                        {inc.related_ips?.length > 0 && `IPs: ${inc.related_ips.join(', ')}`}
                      </p>
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
                        <span className="text-dark-200 text-xs">{inc.risk_score.toFixed(0)}</span>
                      </div>
                    </td>
                    <td className="py-3 px-4 text-dark-200">{inc.confidence.toFixed(0)}%</td>
                    <td className="py-3 px-4">
                      <span className="text-xs font-medium text-dark-300 bg-dark-600 px-2 py-1 rounded-full capitalize">{inc.status}</span>
                    </td>
                    <td className="py-3 px-4 text-dark-300">{inc.event_count}</td>
                    <td className="py-3 px-4 text-dark-400 text-xs">{formatDate(inc.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
