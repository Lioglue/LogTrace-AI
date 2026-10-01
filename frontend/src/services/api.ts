const API_BASE = '/api';

function getToken(): string | null {
  return localStorage.getItem('logtrace_token');
}

function extractErrorMessage(error: any): string {
  if (!error) return 'Request failed';
  if (typeof error.detail === 'string') return error.detail;
  if (Array.isArray(error.detail)) {
    return error.detail
      .map((item: any) => item?.msg || JSON.stringify(item))
      .join(', ');
  }
  if (typeof error.message === 'string') return error.message;
  if (typeof error === 'string') return error;
  return 'Request failed';
}

async function apiRequest<T>(
  path: string,
  options: RequestInit = {}
): Promise<T> {
  const token = getToken();
  const headers: Record<string, string> = {
    ...(options.headers as Record<string, string> || {}),
  };

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  if (!(options.body instanceof FormData)) {
    headers['Content-Type'] = 'application/json';
  }

  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, {
      ...options,
      headers,
    });
  } catch (err) {
    throw new Error('Cannot reach the backend server. Make sure it is running on port 8000.');
  }

  if (response.status === 401) {
    localStorage.removeItem('logtrace_token');
    localStorage.removeItem('logtrace_user');
    window.location.href = '/login';
    throw new Error('Session expired. Please log in again.');
  }

  if (!response.ok) {
    const error = await response.json().catch(() => null);
    throw new Error(extractErrorMessage(error) || `Request failed (${response.status})`);
  }

  return response.json();
}

export const api = {
  auth: {
    register: (data: { username: string; email: string; password: string }) =>
      apiRequest<any>('/auth/register', { method: 'POST', body: JSON.stringify(data) }),
    login: (data: { username: string; password: string }) =>
      apiRequest<any>('/auth/login', { method: 'POST', body: JSON.stringify(data) }),
    me: () => apiRequest<any>('/auth/me'),
  },
  logs: {
    upload: async (file: File, sourceType: string = 'auto') => {
      const formData = new FormData();
      formData.append('file', file);
      formData.append('source_type', sourceType);
      const token = getToken();
      const headers: Record<string, string> = {};
      if (token) headers['Authorization'] = `Bearer ${token}`;

      let response: Response;
      try {
        response = await fetch(`${API_BASE}/logs/upload`, {
          method: 'POST',
          headers,
          body: formData,
        });
      } catch (err) {
        throw new Error('Cannot reach the backend server. Make sure it is running on port 8000.');
      }

      if (!response.ok) {
        const error = await response.json().catch(() => null);
        throw new Error(extractErrorMessage(error) || `Upload failed (${response.status})`);
      }
      return response.json();
    },
    list: (skip = 0, limit = 50) =>
      apiRequest<any[]>(`/logs?skip=${skip}&limit=${limit}`),
    get: (id: number) => apiRequest<any>(`/logs/${id}`),
  },
  events: {
    list: (params: Record<string, string | boolean | number> = {}) => {
      const query = new URLSearchParams();
      Object.entries(params).forEach(([k, v]) => {
        if (v !== undefined && v !== null && v !== '') query.set(k, String(v));
      });
      return apiRequest<any[]>(`/events?${query.toString()}`);
    },
    get: (id: number) => apiRequest<any>(`/events/${id}`),
  },
  incidents: {
    list: (params: Record<string, string> = {}) => {
      const query = new URLSearchParams(params);
      return apiRequest<any[]>(`/incidents?${query.toString()}`);
    },
    get: (id: number) => apiRequest<any>(`/incidents/${id}`),
    update: (id: number, data: any) =>
      apiRequest<any>(`/incidents/${id}`, { method: 'PATCH', body: JSON.stringify(data) }),
    getStory: (id: number) => apiRequest<any>(`/incidents/${id}/story`),
  },
  analytics: {
    dashboard: () => apiRequest<any>('/analytics/dashboard'),
    events: () => apiRequest<any>('/analytics/events'),
  },
  demo: {
    load: () => apiRequest<any>('/demo/load', { method: 'POST' }),
  },
};