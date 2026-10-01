export function formatDate(dateString?: string): string {
  if (!dateString) return 'N/A';
  const date = new Date(dateString);
  return date.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

export function formatTime(dateString?: string): string {
  if (!dateString) return 'N/A';
  const date = new Date(dateString);
  return date.toLocaleTimeString('en-US', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

export function getSeverityColor(severity?: string): string {
  switch (severity) {
    case 'critical': return 'text-red-400 bg-red-900/50';
    case 'high': return 'text-orange-400 bg-orange-900/50';
    case 'medium': return 'text-yellow-400 bg-yellow-900/50';
    case 'low': return 'text-green-400 bg-green-900/50';
    default: return 'text-gray-400 bg-gray-900/50';
  }
}

export function getSeverityBadge(severity?: string): string {
  switch (severity) {
    case 'critical': return 'badge-critical';
    case 'high': return 'badge-high';
    case 'medium': return 'badge-medium';
    case 'low': return 'badge-low';
    default: return 'badge-low';
  }
}

export function getRiskColor(score: number): string {
  if (score >= 76) return '#ef4444';
  if (score >= 51) return '#f97316';
  if (score >= 26) return '#eab308';
  return '#22c55e';
}

export function getRiskLabel(score: number): string {
  if (score >= 76) return 'Critical';
  if (score >= 51) return 'High';
  if (score >= 26) return 'Medium';
  return 'Low';
}

export function truncate(str: string, len: number): string {
  if (str.length <= len) return str;
  return str.substring(0, len) + '...';
}
