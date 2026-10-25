import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { api } from '../services/api';
import { IncidentDetail, AttackStory } from '../types';
import { getSeverityColor, getRiskColor, getRiskLabel, formatDate, formatTime } from '../utils';
import { ArrowLeft, Play, Pause, RotateCcw, BookOpen, Clock } from 'lucide-react';

export default function IncidentDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [incident, setIncident] = useState<IncidentDetail | null>(null);
  const [story, setStory] = useState<AttackStory | null>(null);
  const [loading, setLoading] = useState(true);
  const [replayIndex, setReplayIndex] = useState(-1);
  const [replaying, setReplaying] = useState(false);
  const [replaySpeed, setReplaySpeed] = useState(1500);

  useEffect(() => {
    if (!id) return;
    const incidentId = parseInt(id);
    Promise.all([
      api.incidents.get(incidentId),
      api.incidents.getStory(incidentId).catch(() => null),
    ])
      .then(([inc, st]) => { setIncident(inc); setStory(st); })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [id]);

  const startReplay = () => {
    if (!story || story.entries.length === 0) return;
    setReplayIndex(0);
    setReplaying(true);
  };

  useEffect(() => {
    if (!replaying || !story) return;
    if (replayIndex >= story.entries.length - 1) {
      setReplaying(false);
      return;
    }
    const timer = setTimeout(() => setReplayIndex((i) => i + 1), replaySpeed);
    return () => clearTimeout(timer);
  }, [replaying, replayIndex, replaySpeed, story]);

  const handleStatusChange = async (newStatus: string) => {
    if (!id) return;
    try {
      await api.incidents.update(parseInt(id), { status: newStatus });
      setIncident((prev) => prev ? { ...prev, status: newStatus } : prev);
    } catch (err) { console.error(err); }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="w-8 h-8 border-2 border-cyber-blue border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  if (!incident) {
    return <div className="text-center py-20 text-dark-400">Incident not found</div>;
  }

  return (
    <div className="space-y-8">
      <div className="flex items-center gap-4">
        <Link to="/incidents" className="text-dark-400 hover:text-white">
          <ArrowLeft className="w-5 h-5" />
        </Link>
        <div className="flex-1">
          <h1 className="text-2xl font-bold text-white">{incident.title}</h1>
          <p className="text-dark-400 mt-1">Incident #{incident.id}</p>
        </div>
        <select
          value={incident.status}
          onChange={(e) => handleStatusChange(e.target.value)}
          className="input-field"
        >
          <option value="open">Open</option>
          <option value="investigating">Investigating</option>
          <option value="resolved">Resolved</option>
          <option value="closed">Closed</option>
        </select>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="card text-center">
          <p className="text-sm text-dark-400 mb-1">Severity</p>
          <span className={getSeverityColor(incident.severity) + ' px-3 py-1 rounded-full text-sm font-bold'}>
            {incident.severity?.toUpperCase()}
          </span>
        </div>
        <div className="card text-center">
          <p className="text-sm text-dark-400 mb-1">Risk Score</p>
          <p className="text-2xl font-bold" style={{ color: getRiskColor(incident.risk_score) }}>
            {incident.risk_score.toFixed(0)}
          </p>
          <p className="text-xs text-dark-500">{getRiskLabel(incident.risk_score)}</p>
        </div>
        <div className="card text-center">
          <p className="text-sm text-dark-400 mb-1">Confidence</p>
          <p className="text-2xl font-bold text-white">{incident.confidence.toFixed(0)}%</p>
          <p className="text-xs text-dark-500">Evidence strength</p>
        </div>
        <div className="card text-center">
          <p className="text-sm text-dark-400 mb-1">Events</p>
          <p className="text-2xl font-bold text-white">{incident.event_count}</p>
          <p className="text-xs text-dark-500">Related events</p>
        </div>
      </div>

      <div className="card">
        <h2 className="text-lg font-semibold text-white mb-2">Description</h2>
        <p className="text-dark-300">{incident.description}</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="card">
          <h3 className="text-sm font-medium text-dark-400 mb-2">Related IP Addresses</h3>
          <div className="space-y-1">
            {incident.related_ips?.length > 0 ? incident.related_ips.map((ip) => (
              <span key={ip} className="inline-block bg-dark-700 text-dark-200 px-2 py-1 rounded text-sm font-mono mr-2 mb-1">{ip}</span>
            )) : <span className="text-dark-500 text-sm">None detected</span>}
          </div>
        </div>
        <div className="card">
          <h3 className="text-sm font-medium text-dark-400 mb-2">Related Users</h3>
          <div className="space-y-1">
            {incident.related_users?.length > 0 ? incident.related_users.map((u) => (
              <span key={u} className="inline-block bg-dark-700 text-dark-200 px-2 py-1 rounded text-sm mr-2 mb-1">{u}</span>
            )) : <span className="text-dark-500 text-sm">None detected</span>}
          </div>
        </div>
        <div className="card">
          <h3 className="text-sm font-medium text-dark-400 mb-2">Detection Reasons</h3>
          <div className="space-y-1">
            {incident.detection_reasons?.length > 0 ? incident.detection_reasons.map((r, i) => (
              <p key={i} className="text-dark-300 text-sm">{r}</p>
            )) : <span className="text-dark-500 text-sm">None</span>}
          </div>
        </div>
      </div>

      {story && story.entries.length > 0 && (
        <div className="card">
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-2">
              <BookOpen className="w-5 h-5 text-cyber-blue" />
              <h2 className="text-lg font-semibold text-white">Attack Story</h2>
            </div>
            <div className="flex items-center gap-2">
              <select
                value={replaySpeed}
                onChange={(e) => setReplaySpeed(parseInt(e.target.value))}
                className="input-field text-sm py-1"
              >
                <option value="500">Fast (0.5s)</option>
                <option value="1500">Normal (1.5s)</option>
                <option value="3000">Slow (3s)</option>
              </select>
              {replaying ? (
                <button onClick={() => setReplaying(false)} className="btn-secondary text-sm py-1 flex items-center gap-1">
                  <Pause className="w-3 h-3" /> Pause
                </button>
              ) : (
                <button onClick={startReplay} className="btn-primary text-sm py-1 flex items-center gap-1">
                  <Play className="w-3 h-3" /> {replayIndex >= 0 ? 'Resume' : 'Replay'}
                </button>
              )}
              <button onClick={() => { setReplayIndex(-1); setReplaying(false); }} className="btn-secondary text-sm py-1 flex items-center gap-1">
                <RotateCcw className="w-3 h-3" /> Restart
              </button>
            </div>
          </div>

          {story.summary && (
            <div className="bg-dark-700 rounded-lg p-4 mb-6">
              <p className="text-dark-200 text-sm">{story.summary}</p>
            </div>
          )}

          <div className="relative">
            <div className="absolute left-4 top-0 bottom-0 w-0.5 bg-dark-600" />
            <div className="space-y-6">
              {story.entries.map((entry, index) => {
                const isVisible = replayIndex === -1 || index <= replayIndex;
                return (
                  <div
                    key={entry.id}
                    className={`relative pl-10 transition-opacity duration-500 ${
                      isVisible ? 'opacity-100' : 'opacity-20'
                    }`}
                  >
                    <div className={`absolute left-2.5 w-3 h-3 rounded-full border-2 ${
                      index <= replayIndex ? 'bg-cyber-blue border-cyber-blue' : 'bg-dark-600 border-dark-500'
                    }`} />
                    <div className="bg-dark-700 rounded-lg p-4">
                      <div className="flex items-center gap-2 mb-1">
                        <Clock className="w-3 h-3 text-dark-400" />
                        <span className="text-xs text-dark-400">{formatDate(entry.timestamp)}</span>
                        {entry.severity && (
                          <span className={getSeverityColor(entry.severity) + ' px-1.5 py-0.5 rounded text-xs font-medium'}>
                            {entry.severity.toUpperCase()}
                          </span>
                        )}
                      </div>
                      <h4 className="text-white font-medium text-sm">{entry.title}</h4>
                      {entry.description && (
                        <p className="text-dark-300 text-sm mt-1">{entry.description}</p>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {story.conclusion && (
            <div className="mt-6 bg-dark-700 border-l-4 border-cyber-blue rounded-lg p-4">
              <h4 className="text-white font-medium mb-2">Conclusion</h4>
              <p className="text-dark-300 text-sm">{story.conclusion}</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
