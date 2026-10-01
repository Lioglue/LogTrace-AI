import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { Settings as SettingsIcon, User, Shield, Bell, Sliders } from 'lucide-react';

export default function SettingsPage() {
  const { user } = useAuth();
  const [activeTab, setActiveTab] = useState('profile');

  const tabs = [
    { id: 'profile', label: 'Profile', icon: User },
    { id: 'detection', label: 'Detection Rules', icon: Shield },
    { id: 'correlation', label: 'Correlation', icon: Sliders },
  ];

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <SettingsIcon className="w-6 h-6 text-cyber-blue" />
          Settings
        </h1>
        <p className="text-dark-400 mt-1">Configure your LogTrace AI instance</p>
      </div>

      <div className="flex gap-6">
        <div className="w-56 space-y-1">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-3 w-full px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                activeTab === tab.id
                  ? 'bg-cyber-blue/20 text-cyber-blue'
                  : 'text-dark-300 hover:text-dark-100 hover:bg-dark-700'
              }`}
            >
              <tab.icon className="w-4 h-4" />
              {tab.label}
            </button>
          ))}
        </div>

        <div className="flex-1">
          {activeTab === 'profile' && (
            <div className="card max-w-xl">
              <h2 className="text-lg font-semibold text-white mb-6">Profile Information</h2>
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-dark-200 mb-1.5">Username</label>
                  <input type="text" value={user?.username || ''} disabled className="input-field w-full opacity-60" />
                </div>
                <div>
                  <label className="block text-sm font-medium text-dark-200 mb-1.5">Email</label>
                  <input type="email" value={user?.email || ''} disabled className="input-field w-full opacity-60" />
                </div>
                <div>
                  <label className="block text-sm font-medium text-dark-200 mb-1.5">Account Created</label>
                  <input type="text" value={user?.created_at ? new Date(user.created_at).toLocaleDateString() : 'N/A'} disabled className="input-field w-full opacity-60" />
                </div>
              </div>
              <p className="text-dark-500 text-xs mt-4">Profile editing will be available in a future update.</p>
            </div>
          )}

          {activeTab === 'detection' && (
            <div className="card max-w-xl">
              <h2 className="text-lg font-semibold text-white mb-6">Detection Thresholds</h2>
              <div className="space-y-6">
                <div>
                  <label className="block text-sm font-medium text-dark-200 mb-1.5">
                    Failed Login Threshold
                  </label>
                  <p className="text-xs text-dark-400 mb-2">Number of failed logins before triggering an alert</p>
                  <input type="number" defaultValue={5} min={1} max={50} className="input-field w-32" />
                </div>
                <div>
                  <label className="block text-sm font-medium text-dark-200 mb-1.5">
                    Failed Login Window (minutes)
                  </label>
                  <p className="text-xs text-dark-400 mb-2">Time window for counting failed login attempts</p>
                  <input type="number" defaultValue={5} min={1} max={60} className="input-field w-32" />
                </div>
                <div>
                  <label className="block text-sm font-medium text-dark-200 mb-1.5">
                    Sequence Detection Window (minutes)
                  </label>
                  <p className="text-xs text-dark-400 mb-2">Time window for detecting failed-then-success sequences</p>
                  <input type="number" defaultValue={10} min={1} max={120} className="input-field w-32" />
                </div>
              </div>
              <p className="text-dark-500 text-xs mt-4">Changes will apply to future log processing.</p>
            </div>
          )}

          {activeTab === 'correlation' && (
            <div className="card max-w-xl">
              <h2 className="text-lg font-semibold text-white mb-6">Correlation Settings</h2>
              <div className="space-y-6">
                <div>
                  <label className="block text-sm font-medium text-dark-200 mb-1.5">
                    Correlation Time Window (minutes)
                  </label>
                  <p className="text-xs text-dark-400 mb-2">Maximum time difference for correlating events</p>
                  <input type="number" defaultValue={15} min={1} max={120} className="input-field w-32" />
                </div>
                <div>
                  <label className="block text-sm font-medium text-dark-200 mb-1.5">
                    Correlation Threshold
                  </label>
                  <p className="text-xs text-dark-400 mb-2">Minimum correlation score to consider events related (0-100)</p>
                  <input type="number" defaultValue={50} min={10} max={100} className="input-field w-32" />
                </div>
                <div>
                  <label className="block text-sm font-medium text-dark-200 mb-2">Scoring Weights</label>
                  <div className="grid grid-cols-2 gap-3">
                    {[
                      { label: 'Same IP Address', default: 30 },
                      { label: 'Same Username', default: 25 },
                      { label: 'Same Hostname', default: 15 },
                      { label: 'Same Source System', default: 10 },
                      { label: 'Within 5 minutes', default: 20 },
                      { label: 'Related Sequence', default: 30 },
                    ].map((item) => (
                      <div key={item.label} className="flex items-center justify-between bg-dark-700 rounded-lg p-3">
                        <span className="text-sm text-dark-300">{item.label}</span>
                        <span className="text-sm text-dark-200 font-mono">+{item.default}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
              <p className="text-dark-500 text-xs mt-4">Correlation weights are displayed for reference. Customization will be available in a future update.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
