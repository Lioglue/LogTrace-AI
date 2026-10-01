import React, { useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../services/api';
import { Upload as UploadIcon, File, CheckCircle, XCircle, Loader2 } from 'lucide-react';

const SOURCE_TYPES = [
  { value: 'auto', label: 'Auto Detect' },
  { value: 'auth', label: 'Authentication' },
  { value: 'web', label: 'Web Server' },
  { value: 'firewall', label: 'Firewall' },
  { value: 'application', label: 'Application' },
  { value: 'system', label: 'System' },
];

export default function UploadPage() {
  const [file, setFile] = useState<File | null>(null);
  const [sourceType, setSourceType] = useState('auto');
  const [uploading, setUploading] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState('');
  const [dragOver, setDragOver] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();

  const handleFile = (f: File) => {
    const ext = f.name.split('.').pop()?.toLowerCase();
    if (!['log', 'txt', 'csv'].includes(ext || '')) {
      setError('Only .log, .txt, and .csv files are supported');
      return;
    }
    if (f.size > 50 * 1024 * 1024) {
      setError('File size exceeds 50MB limit');
      return;
    }
    setFile(f);
    setError('');
    setResult(null);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const f = e.dataTransfer.files[0];
    if (f) handleFile(f);
  };

  const handleUpload = async () => {
    if (!file) return;
    setUploading(true);
    setError('');
    try {
      const res = await api.logs.upload(file, sourceType);
      setResult(res);
    } catch (err: any) {
      setError(err.message || 'Upload failed');
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-8">
      <div>
        <h1 className="text-2xl font-bold text-white">Upload Logs</h1>
        <p className="text-dark-400 mt-1">Upload security log files for analysis</p>
      </div>

      <div className="card">
        <div
          onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
          onDragLeave={() => setDragOver(false)}
          onDrop={handleDrop}
          onClick={() => fileInputRef.current?.click()}
          className={`border-2 border-dashed rounded-xl p-12 text-center cursor-pointer transition-colors ${
            dragOver ? 'border-cyber-blue bg-cyber-blue/10' : 'border-dark-600 hover:border-dark-500'
          }`}
        >
          <input
            ref={fileInputRef}
            type="file"
            accept=".log,.txt,.csv"
            onChange={(e) => e.target.files?.[0] && handleFile(e.target.files[0])}
            className="hidden"
          />
          <UploadIcon className="w-12 h-12 text-dark-400 mx-auto mb-4" />
          {file ? (
            <div className="flex items-center justify-center gap-3">
              <File className="w-5 h-5 text-cyber-blue" />
              <span className="text-white font-medium">{file.name}</span>
              <span className="text-dark-400 text-sm">({(file.size / 1024).toFixed(1)} KB)</span>
            </div>
          ) : (
            <>
              <p className="text-dark-300 mb-2">Drag and drop your log file here, or click to browse</p>
              <p className="text-dark-500 text-sm">Supports .log, .txt, .csv (max 50MB)</p>
            </>
          )}
        </div>

        <div className="mt-6 flex items-end gap-4">
          <div className="flex-1">
            <label className="block text-sm font-medium text-dark-200 mb-1.5">Source Type</label>
            <select
              value={sourceType}
              onChange={(e) => setSourceType(e.target.value)}
              className="input-field w-full"
            >
              {SOURCE_TYPES.map((st) => (
                <option key={st.value} value={st.value}>{st.label}</option>
              ))}
            </select>
          </div>
          <button
            onClick={handleUpload}
            disabled={!file || uploading}
            className="btn-primary px-8 py-2.5 flex items-center gap-2 disabled:opacity-50"
          >
            {uploading ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                Processing...
              </>
            ) : (
              <>
                <UploadIcon className="w-4 h-4" />
                Upload & Analyze
              </>
            )}
          </button>
        </div>
      </div>

      {error && (
        <div className="bg-red-900/30 border border-red-800 text-red-400 px-4 py-3 rounded-lg flex items-center gap-2">
          <XCircle className="w-5 h-5 flex-shrink-0" />
          {error}
        </div>
      )}

      {result && (
        <div className="card">
          <div className="flex items-center gap-2 mb-4">
            <CheckCircle className="w-5 h-5 text-cyber-green" />
            <h3 className="text-lg font-semibold text-white">Processing Complete</h3>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
            <div className="bg-dark-700 rounded-lg p-4">
              <p className="text-sm text-dark-400">Status</p>
              <p className="text-lg font-bold text-cyber-green capitalize">{result.processing_status}</p>
            </div>
            <div className="bg-dark-700 rounded-lg p-4">
              <p className="text-sm text-dark-400">Events Parsed</p>
              <p className="text-lg font-bold text-white">{result.event_count}</p>
            </div>
            <div className="bg-dark-700 rounded-lg p-4">
              <p className="text-sm text-dark-400">Suspicious Events</p>
              <p className="text-lg font-bold text-cyber-yellow">{result.suspicious_count}</p>
            </div>
            {typeof result.lines_total === 'number' && result.lines_total > 0 && (
              <div className="bg-dark-700 rounded-lg p-4">
                <p className="text-sm text-dark-400">Lines / Parsed</p>
                <p className="text-lg font-bold text-white">{result.lines_total} / {result.lines_parsed}</p>
              </div>
            )}
            {result.detected_format && (
              <div className="bg-dark-700 rounded-lg p-4">
                <p className="text-sm text-dark-400">Detected Format</p>
                <p className="text-lg font-bold text-cyber-blue capitalize">{result.detected_format}</p>
              </div>
            )}
            {typeof result.lines_skipped === 'number' && result.lines_skipped > 0 && (
              <div className="bg-dark-700 rounded-lg p-4">
                <p className="text-sm text-dark-400">Lines Skipped</p>
                <p className="text-lg font-bold text-red-400">{result.lines_skipped}</p>
              </div>
            )}
          </div>
          {(result.processing_notes || (result.warnings && result.warnings.length > 0)) && (
            <div className="mt-4 bg-dark-700/60 border border-dark-600 rounded-lg p-4">
              <p className="text-sm font-medium text-amber-400 mb-2">Analysis Notes</p>
              {result.warnings && result.warnings.length > 0 ? (
                <ul className="space-y-1">
                  {result.warnings.map((w: string, i: number) => (
                    <li key={i} className="text-sm text-dark-300">{w}</li>
                  ))}
                </ul>
              ) : (
                <p className="text-sm text-dark-300">{result.processing_notes}</p>
              )}
            </div>
          )}
          <div className="mt-4 flex gap-3">
            <button onClick={() => navigate('/explorer')} className="btn-secondary">View Events</button>
            <button onClick={() => navigate('/incidents')} className="btn-secondary">View Incidents</button>
            <button onClick={() => { setFile(null); setResult(null); }} className="btn-primary">Upload Another</button>
          </div>
        </div>
      )}
    </div>
  );
}
