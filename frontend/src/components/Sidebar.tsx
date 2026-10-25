import React from 'react';
import { Outlet, NavLink, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import {
  LayoutDashboard, Upload, Search, AlertTriangle,
  BookOpen, BarChart3, Settings, LogOut, Shield,
} from 'lucide-react';

const navItems = [
  { to: '/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/upload', icon: Upload, label: 'Upload Logs' },
  { to: '/explorer', icon: Search, label: 'Log Explorer' },
  { to: '/incidents', icon: AlertTriangle, label: 'Incidents' },
  { to: '/stories', icon: BookOpen, label: 'Attack Stories' },
  { to: '/analytics', icon: BarChart3, label: 'Analytics' },
  { to: '/settings', icon: Settings, label: 'Settings' },
];

export default function Sidebar() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <aside className="w-64 bg-dark-800 border-r border-dark-700 flex flex-col h-screen fixed left-0 top-0 z-30">
      <div className="p-6 border-b border-dark-700">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 bg-cyber-blue rounded-lg flex items-center justify-center">
            <Shield className="w-6 h-6 text-white" />
          </div>
          <div>
            <h1 className="text-lg font-bold text-white">LogTrace AI</h1>
            <p className="text-xs text-dark-400">Security Analytics</p>
          </div>
        </div>
      </div>

      <nav className="flex-1 p-4 space-y-1 overflow-y-auto">
        {navItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors duration-200 ${
                isActive
                  ? 'bg-cyber-blue/20 text-cyber-blue'
                  : 'text-dark-300 hover:text-dark-100 hover:bg-dark-700'
              }`
            }
          >
            <item.icon className="w-5 h-5" />
            {item.label}
          </NavLink>
        ))}
      </nav>

      <div className="p-4 border-t border-dark-700">
        <div className="flex items-center gap-3 mb-3 px-3">
          <div className="w-8 h-8 bg-dark-600 rounded-full flex items-center justify-center">
            <span className="text-sm font-medium text-dark-200">
              {user?.username?.[0]?.toUpperCase() || 'U'}
            </span>
          </div>
          <span className="text-sm text-dark-300 truncate">{user?.username}</span>
        </div>
        <button
          onClick={handleLogout}
          className="flex items-center gap-3 w-full px-3 py-2.5 rounded-lg text-sm font-medium text-dark-300 hover:text-red-400 hover:bg-dark-700 transition-colors duration-200"
        >
          <LogOut className="w-5 h-5" />
          Logout
        </button>
      </div>
    </aside>
  );
}
