import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../services/api';
import { Incident } from '../types';
import { getSeverityColor, getRiskColor, formatDate } from '../utils';
import { BookOpen, ArrowRight } from 'lucide-react';

export default function StoriesPage() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.incidents.list()
      .then(setIncidents)
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Attack Stories</h1>
        <p className="text-dark-400 mt-1">Reconstructed timelines of potential security incidents</p>
      </div>

      {loading ? (
        <div className="flex items-center justify-center h-32">
          <div className="w-8 h-8 border-2 border-cyber-blue border-t-transparent rounded-full animate-spin" />
        </div>
      ) : incidents.length === 0 ? (
        <div className="card text-center py-16">
          <BookOpen className="w-12 h-12 text-dark-500 mx-auto mb-4" />
          <p className="text-dark-400 text-lg">No attack stories yet</p>
          <p className="text-dark-500 text-sm mt-2">Upload logs to generate attack stories</p>
        </div>
      ) : (
        <div className="space-y-4">
          {incidents.map((inc) => (
            <Link
              key={inc.id}
              to={`/incidents/${inc.id}`}
              className="card block hover:border-dark-500 transition-colors group"
            >
              <div className="flex items-center justify-between">
                <div className="flex-1">
                  <div className="flex items-center gap-3 mb-2">
                    <span className={getSeverityColor(inc.severity) + ' px-2 py-0.5 rounded-full text-xs font-bold'}>
                      {inc.severity?.toUpperCase()}
                    </span>
                    <span className="text-dark-400 text-sm">#{inc.id}</span>
                  </div>
                  <h3 className="text-white font-semibold group-hover:text-cyber-blue transition-colors">{inc.title}</h3>
                  <p className="text-dark-400 text-sm mt-1 line-clamp-2">{inc.description}</p>
                  <div className="flex items-center gap-6 mt-3">
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-dark-500">Risk:</span>
                      <div className="w-20 h-1.5 bg-dark-600 rounded-full overflow-hidden">
                        <div className="h-full rounded-full" style={{ width: `${inc.risk_score}%`, backgroundColor: getRiskColor(inc.risk_score) }} />
                      </div>
                      <span className="text-xs text-dark-300">{inc.risk_score.toFixed(0)}</span>
                    </div>
                    <div className="flex items-center gap-1">
                      <span className="text-xs text-dark-500">Confidence:</span>
                      <span className="text-xs text-dark-300">{inc.confidence.toFixed(0)}%</span>
                    </div>
                    <div className="flex items-center gap-1">
                      <span className="text-xs text-dark-500">Events:</span>
                      <span className="text-xs text-dark-300">{inc.event_count}</span>
                    </div>
                    <span className="text-xs text-dark-500">{formatDate(inc.created_at)}</span>
                  </div>
                </div>
                <ArrowRight className="w-5 h-5 text-dark-500 group-hover:text-cyber-blue transition-colors ml-4" />
              </div>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}
