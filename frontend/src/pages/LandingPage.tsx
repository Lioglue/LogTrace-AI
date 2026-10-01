import React from 'react';
import { Link } from 'react-router-dom';
import {
  Shield, Upload, Search, AlertTriangle, BookOpen,
  BarChart3, ArrowRight, CheckCircle, Zap, Eye,
  Lock, Database, GitBranch,
} from 'lucide-react';

const features = [
  { icon: Database, title: 'Log Analysis', desc: 'Parse and normalize logs from multiple sources' },
  { icon: Search, title: 'Event Normalization', desc: 'Standardize events across different log types' },
  { icon: AlertTriangle, title: 'Suspicious Activity Detection', desc: 'Rule-based detection with explainable alerts' },
  { icon: GitBranch, title: 'Event Correlation', desc: 'Connect related events across time and sources' },
  { icon: Shield, title: 'Incident Detection', desc: 'Cluster correlated events into potential incidents' },
  { icon: BarChart3, title: 'Risk Scoring', desc: 'Calculate risk and confidence for each incident' },
  { icon: Eye, title: 'Incident Confidence', desc: 'Separate risk from evidence strength' },
  { icon: BookOpen, title: 'Attack Story Timeline', desc: 'Reconstruct chronological investigation narratives' },
  { icon: Zap, title: 'Incident Replay', desc: 'Walk through events step by step' },
  { icon: Lock, title: 'Secure Authentication', desc: 'JWT-based user authentication and protection' },
];

const steps = [
  { num: 1, title: 'Upload Logs', desc: 'Upload .log, .txt, or .csv files from any source' },
  { num: 2, title: 'Parse Events', desc: 'Automatically detect format and extract structured data' },
  { num: 3, title: 'Detect Suspicious Activity', desc: 'Apply detection rules to identify potential threats' },
  { num: 4, title: 'Correlate Related Events', desc: 'Connect events that share common attributes' },
  { num: 5, title: 'Investigate the Attack Story', desc: 'Review the reconstructed timeline of events' },
];

export default function LandingPage() {
  return (
    <div className="min-h-screen bg-dark-900">
      <header className="border-b border-dark-700">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-cyber-blue rounded-lg flex items-center justify-center">
              <Shield className="w-6 h-6 text-white" />
            </div>
            <span className="text-xl font-bold text-white">LogTrace AI</span>
          </div>
          <div className="flex items-center gap-4">
            <Link to="/login" className="btn-secondary">Login</Link>
            <Link to="/register" className="btn-primary">Get Started</Link>
          </div>
        </div>
      </header>

      <section className="max-w-7xl mx-auto px-6 py-20 text-center">
        <h1 className="text-5xl font-bold text-white mb-6 leading-tight">
          Turn Raw Logs Into<br />
          <span className="text-cyber-blue">Clear Security Stories</span>
        </h1>
        <p className="text-xl text-dark-300 max-w-3xl mx-auto mb-10">
          LogTrace AI analyzes security logs, detects suspicious activity, connects
          related events, and reconstructs possible incidents into understandable
          Attack Stories.
        </p>
        <div className="flex items-center justify-center gap-4">
          <Link to="/register" className="btn-primary text-lg px-8 py-3 flex items-center gap-2">
            Get Started <ArrowRight className="w-5 h-5" />
          </Link>
          <Link to="/login" className="btn-secondary text-lg px-8 py-3">
            View Demo
          </Link>
        </div>
      </section>

      <section className="max-w-7xl mx-auto px-6 py-20">
        <h2 className="text-3xl font-bold text-white text-center mb-12">How It Works</h2>
        <div className="grid grid-cols-1 md:grid-cols-5 gap-8">
          {steps.map((step) => (
            <div key={step.num} className="text-center">
              <div className="w-12 h-12 bg-cyber-blue/20 text-cyber-blue rounded-full flex items-center justify-center mx-auto mb-4 text-xl font-bold">
                {step.num}
              </div>
              <h3 className="text-lg font-semibold text-white mb-2">{step.title}</h3>
              <p className="text-sm text-dark-300">{step.desc}</p>
            </div>
          ))}
        </div>
      </section>

      <section className="max-w-7xl mx-auto px-6 py-20">
        <h2 className="text-3xl font-bold text-white text-center mb-4">Features</h2>
        <p className="text-dark-300 text-center mb-12 max-w-2xl mx-auto">
          A focused log analysis and incident investigation platform built to help
          security analysts understand how separate events may be connected.
        </p>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {features.map((feature) => (
            <div key={feature.title} className="card hover:border-dark-500 transition-colors">
              <feature.icon className="w-8 h-8 text-cyber-blue mb-3" />
              <h3 className="text-lg font-semibold text-white mb-2">{feature.title}</h3>
              <p className="text-sm text-dark-300">{feature.desc}</p>
            </div>
          ))}
        </div>
      </section>

      <section className="max-w-7xl mx-auto px-6 py-20">
        <div className="card max-w-4xl mx-auto">
          <h2 className="text-2xl font-bold text-white mb-4">How LogTrace AI Differs from a Traditional SIEM</h2>
          <p className="text-dark-300 mb-4">
            A traditional SIEM focuses on log collection, centralized storage, monitoring,
            searching, alert generation, reporting, and compliance.
          </p>
          <p className="text-dark-300 mb-4">
            LogTrace AI focuses specifically on:
          </p>
          <ul className="space-y-2 mb-6">
            {['Log understanding and normalization', 'Suspicious pattern detection with explanations',
              'Event correlation with scoring', 'Incident clustering', 'Risk and confidence scoring',
              'Attack Story reconstruction'].map((item) => (
              <li key={item} className="flex items-center gap-2 text-dark-200">
                <CheckCircle className="w-4 h-4 text-cyber-green flex-shrink-0" />
                {item}
              </li>
            ))}
          </ul>
          <p className="text-sm text-dark-400">
            LogTrace AI is not intended as a complete enterprise SIEM replacement.
            It is a focused project whose primary feature is making event relationships
            and incident reconstruction easier to understand.
          </p>
        </div>
      </section>

      <footer className="border-t border-dark-700 py-8">
        <div className="max-w-7xl mx-auto px-6 text-center text-dark-400 text-sm">
          LogTrace AI - Cybersecurity Log Analysis Platform
        </div>
      </footer>
    </div>
  );
}
