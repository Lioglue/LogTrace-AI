import React, { useEffect, useState, useCallback } from 'react';
import { api } from '../services/api';
import { LogEvent } from '../types';
import { getSeverityColor, formatDate, truncate } from '../utils';
import { Search, Filter, ChevronLeft, ChevronRight, X } from 'lucide-react';

export default function ExplorerPage() {
  const [events, setEvents] = useState<LogEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedEvent, setSelectedEvent] = useState<any>(null);
  const [page, setPage] = useState(0);
  const [hasMore, setHasMore] = useState(true);
  const limit = 30;

  const [filters, setFilters] = useState({
    search: '',
    ip_address: '',
    username: '',
    severity: '',
    source: '',
    event_type: '',
    suspicious_only: false,
  });

  const loadEvents = useCallback(async () => {
    setLoading(true);
    try {
      const params: Record<string, any> = { skip: page * limit, limit };
      if (filters.search) params.search = filters.search;
      if (filters.ip_address) params.ip_address = filters.ip_address;
      if (filters.username) params.username = filters.username;
      if (filters.severity) params.severity = filters.severity;
      if (filters.source) params.source = filters.source;
      if (filters.event_type) params.event_type = filters.event_type;
      if (filters.suspicious_only) params.suspicious_only = true;

      const data = await api.events.list(params);
      setEvents(data);
      setHasMore(data.length === limit);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  }, [page, filters]);

  useEffect(() => { loadEvents(); }, [loadEvents]);

  const handleEventClick = async (eventId: number) => {
    try {
      const detail = await api.events.get(eventId);
      setSelectedEvent(detail);
    } catch (err) {
      console.error(err);
    }
  };

  const clearFilters = () => {
    setFilters({ search: '', ip_address: '', username: '', severity: '', source: '', event_type: '', suspicious_only: false });
    setPage(0);
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Log Explorer</h1>
        <p className="text-dark-400 mt-1">Search and filter through parsed events</p>
      </div>

      <div className="card">
        <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-4 gap-3 mb-4">
          <div className="relative col-span-1 md:col-span-3 lg:col-span-2">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-dark-400" />
            <input
              type="text"
              placeholder="Search in raw messages..."
              value={filters.search}
              onChange={(e) => { setFilters({ ...filters, search: e.target.value }); setPage(0); }}
              className="input-field w-full pl-10"
            />
          </div>
          <input
            type="text"
            placeholder="IP Address"
            value={filters.ip_address}
            onChange={(e) => { setFilters({ ...filters, ip_address: e.target.value }); setPage(0); }}
            className="input-field"
          />
          <input
            type="text"
            placeholder="Username"
            value={filters.username}
            onChange={(e) => { setFilters({ ...filters, username: e.target.value }); setPage(0); }}
            className="input-field"
          />
          <select
            value={filters.severity}
            onChange={(e) => { setFilters({ ...filters, severity: e.target.value }); setPage(0); }}
            className="input-field"
          >
            <option value="">All Severities</option>
            <option value="low">Low</option>
            <option value="medium">Medium</option>
            <option value="high">High</option>
            <option value="critical">Critical</option>
          </select>
          <select
            value={filters.source}
            onChange={(e) => { setFilters({ ...filters, source: e.target.value }); setPage(0); }}
            className="input-field"
          >
            <option value="">All Sources</option>
            <option value="authentication">Authentication</option>
            <option value="web_server">Web Server</option>
            <option value="firewall">Firewall</option>
            <option value="application">Application</option>
            <option value="system">System</option>
            <option value="generic">Generic</option>
          </select>
          <select
            value={filters.event_type}
            onChange={(e) => { setFilters({ ...filters, event_type: e.target.value }); setPage(0); }}
            className="input-field"
          >
            <option value="">All Event Types</option>
            <option value="LOGIN_FAILED">Login Failed</option>
            <option value="LOGIN_SUCCESS">Login Success</option>
            <option value="ACCESS_DENIED">Access Denied</option>
            <option value="HTTP_REQUEST">HTTP Request</option>
            <option value="FIREWALL_BLOCK">Firewall Block</option>
            <option value="PRIVILEGE_CHANGE">Privilege Change</option>
          </select>
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={filters.suspicious_only}
              onChange={(e) => { setFilters({ ...filters, suspicious_only: e.target.checked }); setPage(0); }}
              className="w-4 h-4 rounded border-dark-600"
            />
            <span className="text-sm text-dark-300">Suspicious Only</span>
          </label>
        </div>

        <div className="flex items-center gap-2">
          <button onClick={clearFilters} className="btn-secondary text-sm py-1.5 flex items-center gap-1">
            <X className="w-3 h-3" /> Clear Filters
          </button>
          <span className="text-sm text-dark-400">{events.length} events loaded</span>
        </div>
      </div>

      <div className="card">
        {loading ? (
          <div className="flex items-center justify-center h-32">
            <div className="w-8 h-8 border-2 border-cyber-blue border-t-transparent rounded-full animate-spin" />
          </div>
        ) : events.length === 0 ? (
          <div className="text-center py-12">
            <p className="text-dark-400">No events found</p>
          </div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-dark-400 border-b border-dark-700">
                    <th className="text-left py-3 px-3">Timestamp</th>
                    <th className="text-left py-3 px-3">Source</th>
                    <th className="text-left py-3 px-3">Event Type</th>
                    <th className="text-left py-3 px-3">IP Address</th>
                    <th className="text-left py-3 px-3">Username</th>
                    <th className="text-left py-3 px-3">Severity</th>
                    <th className="text-left py-3 px-3">Message</th>
                  </tr>
                </thead>
                <tbody>
                  {events.map((event) => (
                    <tr
                      key={event.id}
                      onClick={() => handleEventClick(event.id)}
                      className="border-b border-dark-700/50 hover:bg-dark-700/30 cursor-pointer"
                    >
                      <td className="py-3 px-3 text-dark-300 text-xs whitespace-nowrap">{formatDate(event.timestamp)}</td>
                      <td className="py-3 px-3 text-dark-200">{event.source}</td>
                      <td className="py-3 px-3">
                        <span className="text-dark-200 font-medium">{event.event_type}</span>
                      </td>
                      <td className="py-3 px-3 text-dark-300 font-mono text-xs">{event.ip_address || '-'}</td>
                      <td className="py-3 px-3 text-dark-300">{event.username || '-'}</td>
                      <td className="py-3 px-3">
                        <span className={getSeverityColor(event.severity) + ' px-2 py-0.5 rounded-full text-xs font-medium'}>
                          {event.severity?.toUpperCase()}
                        </span>
                      </td>
                      <td className="py-3 px-3 text-dark-400 text-xs max-w-xs">{truncate(event.raw_message || '', 80)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="flex items-center justify-between mt-4">
              <button
                onClick={() => setPage(Math.max(0, page - 1))}
                disabled={page === 0}
                className="btn-secondary text-sm py-1.5 flex items-center gap-1 disabled:opacity-50"
              >
                <ChevronLeft className="w-4 h-4" /> Previous
              </button>
              <span className="text-sm text-dark-400">Page {page + 1}</span>
              <button
                onClick={() => setPage(page + 1)}
                disabled={!hasMore}
                className="btn-secondary text-sm py-1.5 flex items-center gap-1 disabled:opacity-50"
              >
                Next <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </>
        )}
      </div>

      {selectedEvent && (
        <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4" onClick={() => setSelectedEvent(null)}>
          <div className="bg-dark-800 border border-dark-700 rounded-xl max-w-3xl w-full max-h-[80vh] overflow-y-auto p-6" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-xl font-bold text-white">Event #{selectedEvent.id}</h2>
              <button onClick={() => setSelectedEvent(null)} className="text-dark-400 hover:text-white">X</button>
            </div>

            <div className="grid grid-cols-2 gap-4 mb-6">
              <div><span className="text-dark-400 text-sm">Timestamp</span><p className="text-white">{formatDate(selectedEvent.timestamp)}</p></div>
              <div><span className="text-dark-400 text-sm">Source</span><p className="text-white">{selectedEvent.source}</p></div>
              <div><span className="text-dark-400 text-sm">Event Type</span><p className="text-white">{selectedEvent.event_type}</p></div>
              <div><span className="text-dark-400 text-sm">Severity</span><p className={getSeverityColor(selectedEvent.severity) + ' inline-block px-2 py-0.5 rounded-full text-xs font-medium'}>{selectedEvent.severity?.toUpperCase()}</p></div>
              <div><span className="text-dark-400 text-sm">IP Address</span><p className="text-white font-mono">{selectedEvent.ip_address || 'N/A'}</p></div>
              <div><span className="text-dark-400 text-sm">Username</span><p className="text-white">{selectedEvent.username || 'N/A'}</p></div>
              <div><span className="text-dark-400 text-sm">Hostname</span><p className="text-white">{selectedEvent.hostname || 'N/A'}</p></div>
              <div><span className="text-dark-400 text-sm">Resource</span><p className="text-white">{selectedEvent.resource || 'N/A'}</p></div>
            </div>

            <div className="mb-6">
              <span className="text-dark-400 text-sm">Raw Log Message</span>
              <pre className="mt-1 bg-dark-900 rounded-lg p-4 text-sm text-dark-200 overflow-x-auto whitespace-pre-wrap">{selectedEvent.raw_message}</pre>
            </div>

            {selectedEvent.alerts?.length > 0 && (
              <div className="mb-6">
                <span className="text-dark-400 text-sm mb-2 block">Detection Alerts</span>
                <div className="space-y-2">
                  {selectedEvent.alerts.map((alert: any, i: number) => (
                    <div key={i} className="bg-dark-700 rounded-lg p-3">
                      <p className="text-white font-medium text-sm">{alert.rule_name}</p>
                      <p className="text-dark-300 text-sm mt-1">{alert.description}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {selectedEvent.related_incidents?.length > 0 && (
              <div>
                <span className="text-dark-400 text-sm mb-2 block">Related Incidents</span>
                <div className="space-y-2">
                  {selectedEvent.related_incidents.map((ri: any, i: number) => (
                    <div key={i} className="bg-dark-700 rounded-lg p-3">
                      <p className="text-white text-sm">Incident #{ri.incident_id}</p>
                      <p className="text-dark-400 text-xs">Correlation Score: {ri.correlation_score}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
