import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { api } from '../services/api';
import { User } from '../types';

interface AuthContextType {
  user: User | null;
  token: string | null;
  login: (username: string, password: string) => Promise<void>;
  register: (username: string, email: string, password: string) => Promise<void>;
  logout: () => void;
  loading: boolean;
}

const AuthContext = createContext<AuthContextType>({
  user: null,
  token: null,
  login: async () => {},
  register: async () => {},
  logout: () => {},
  loading: true,
});

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const savedToken = localStorage.getItem('logtrace_token');
    const savedUser = localStorage.getItem('logtrace_user');
    if (savedToken && savedUser) {
      setToken(savedToken);
      setUser(JSON.parse(savedUser));
    }
    setLoading(false);
  }, []);

  const login = async (username: string, password: string) => {
    const response = await api.auth.login({ username, password });
    setToken(response.access_token);
    setUser(response.user);
    localStorage.setItem('logtrace_token', response.access_token);
    localStorage.setItem('logtrace_user', JSON.stringify(response.user));
  };

  const register = async (username: string, email: string, password: string) => {
    const response = await api.auth.register({ username, email, password });
    setToken(response.access_token);
    setUser(response.user);
    localStorage.setItem('logtrace_token', response.access_token);
    localStorage.setItem('logtrace_user', JSON.stringify(response.user));
  };

  const logout = () => {
    setToken(null);
    setUser(null);
    localStorage.removeItem('logtrace_token');
    localStorage.removeItem('logtrace_user');
  };

  return (
    <AuthContext.Provider value={{ user, token, login, register, logout, loading }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext);
