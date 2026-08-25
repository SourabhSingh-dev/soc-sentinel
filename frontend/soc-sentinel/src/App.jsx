import { useState } from 'react';
import axios from 'axios';
import {
  ShieldAlert,
  Activity,
  AlertTriangle,
  Terminal,
  UploadCloud,
  Zap,
  ChevronRight,
} from 'lucide-react';
import { SAMPLE_TELEMETRY } from './assets/sample_payload';
import './App.css';

const TELEMETRY = SAMPLE_TELEMETRY;

function App() {
  const [payload, setPayload] = useState('[\n  \n]');
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleTriage = async () => {
    setLoading(true);
    setError(null);
    setResults(null);

    try {
      const parsedPayload = JSON.parse(payload);
      const API_URL = import.meta.env.VITE_API_URL;

      const response = await axios.post(
          `${API_URL}/triage`,
          parsedPayload
      );
      setResults(response.data.triage_queue);
    } catch (err) {
      if (err instanceof SyntaxError) {
        setError('Invalid JSON format. Check your brackets and commas.');
      } else {
        setError(
          err.response?.data?.detail ||
            err.message ||
            'Network error. Is the backend running?'
        );
      }
    } finally {
      setLoading(false);
    }
  };

  const loadSampleData = () => {
    setPayload(JSON.stringify(TELEMETRY, null, 2));
    setError(null);
  };

  const getThreatStyle = (score) => {
    if (score >= 0.7) {
      return {
        color: '#fb7185',
        bg: 'rgba(244, 63, 94, 0.10)',
        label: 'CRITICAL',
        border: 'rgba(244, 63, 94, 0.35)',
      };
    }

    if (score >= 0.3) {
      return {
        color: '#fbbf24',
        bg: 'rgba(245, 158, 11, 0.10)',
        label: 'HIGH',
        border: 'rgba(245, 158, 11, 0.35)',
      };
    }

    return {
      color: '#34d399',
      bg: 'rgba(16, 185, 129, 0.10)',
      label: 'LOW',
      border: 'rgba(16, 185, 129, 0.35)',
    };
  };

  const criticalCount =
    results?.filter((incident) => incident.threat_score >= 0.7).length ?? 0;

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand">
          <div className="brand-icon">
            <ShieldAlert size={22} strokeWidth={2.2} />
          </div>

          <div>
            <div className="brand-name">
              SOC <span>SENTINEL</span>
            </div>
            <div className="brand-subtitle">Threat Triage Engine</div>
          </div>
        </div>

        <div className="system-status">
          <span className="status-dot" />
          <span>ENGINE ONLINE</span>
        </div>
      </header>

      <main className="dashboard">
        <section className="panel ingestion-panel">
          <div className="panel-heading">
            <div>
              <div className="eyebrow">
                <Terminal size={14} />
                TELEMETRY INGESTION
              </div>
              <h2>Raw event payload</h2>
            </div>

            <button className="secondary-button" onClick={loadSampleData}>
              <UploadCloud size={15} />
              Load sample
            </button>
          </div>

          <div className="editor-shell">
            <div className="editor-bar">
              <div className="editor-dots">
                <span />
                <span />
                <span />
              </div>
              <span className="editor-label">JSON</span>
            </div>

            <textarea
              value={payload}
              onChange={(e) => setPayload(e.target.value)}
              className="json-editor"
              spellCheck="false"
              placeholder="Paste your JSON telemetry payload here..."
            />
          </div>

          <div className="input-footer">
            <span>Expected input: JSON telemetry array</span>
            <span>{payload.length.toLocaleString()} chars</span>
          </div>

          <button
            className="primary-button"
            onClick={handleTriage}
            disabled={loading}
          >
            {loading ? (
              <>
                <Activity size={17} className="spin" />
                Executing pipeline...
              </>
            ) : (
              <>
                <Zap size={17} />
                Run triage engine
              </>
            )}
          </button>

          {error && (
            <div className="error-banner">
              <AlertTriangle size={18} />
              <div>
                <strong>Pipeline error</strong>
                <span>{error}</span>
              </div>
            </div>
          )}
        </section>

        <section className="panel queue-panel">
          <div className="panel-heading queue-heading">
            <div>
              <div className="eyebrow">
                <Activity size={14} />
                PRIORITIZATION OUTPUT
              </div>
              <h2>Ranked incident queue</h2>
            </div>

            {results && (
              <div className="queue-stats">
                <div>
                  <strong>{results.length}</strong>
                  <span>Incidents</span>
                </div>
                <div className="stat-divider" />
                <div className="critical-stat">
                  <strong>{criticalCount}</strong>
                  <span>Critical</span>
                </div>
              </div>
            )}
          </div>

          <div className="queue-scroll">
            {!results && !loading && (
              <div className="empty-state">
                <div className="empty-icon">
                  <ShieldAlert size={28} />
                </div>
                <h3>Awaiting telemetry</h3>
                <p>
                  Load the sample payload or paste raw SOC telemetry, then run
                  the triage engine.
                </p>
              </div>
            )}

            {loading && (
              <div className="empty-state processing-state">
                <div className="processing-icon">
                  <Activity size={28} className="spin" />
                </div>
                <h3>Processing telemetry</h3>
                <p>
                  Running feature extraction, threat scoring and incident
                  prioritization...
                </p>
              </div>
            )}

            {results &&
              results.map((incident, index) => {
                const style = getThreatStyle(incident.threat_score);
                const evidence = incident.evidence?.slice(0, 4) ?? [];
                const hasEncodedFeatures = evidence.some(
                  (ev) =>
                    ev.feature.startsWith('alert_') ||
                    ev.feature.startsWith('file_')
                );

                return (
                  <article
                    className="incident-card"
                    key={incident.incident_id}
                    style={{ '--threat-color': style.color }}
                  >
                    <div className="incident-header">
                      <div className="incident-id">
                        <span className="rank">#{index + 1}</span>
                        <ChevronRight size={14} />
                        <span>INCIDENT-{incident.incident_id}</span>
                      </div>

                      <div className="score-group">
                        <span
                          className="severity-badge"
                          style={{
                            color: style.color,
                            background: style.bg,
                            borderColor: style.border,
                          }}
                        >
                          {style.label}
                        </span>

                        <span
                          className="score"
                          style={{ color: style.color }}
                        >
                          {(incident.threat_score * 100).toFixed(1)}%
                        </span>
                      </div>
                    </div>

                    <div className="evidence-section">
                      <div className="evidence-heading">
                        <span>Model evidence</span>
                        <span className="shap-label">SHAP</span>
                      </div>

                      <div className="evidence-list">
                        {evidence.map((ev) => {
                          const isObfuscated =
                            ev.feature.startsWith('alert_') ||
                            ev.feature.startsWith('file_');

                          return (
                            <div
                              className="evidence-chip"
                              key={ev.feature}
                              title={
                                isObfuscated
                                  ? 'This feature was obfuscated by the data provider.'
                                  : ''
                              }
                            >
                              <span className="feature-name">
                                {ev.feature}
                                {isObfuscated && (
                                  <span className="obfuscated">*</span>
                                )}
                              </span>
                              <span className="shap-value">
                                +{ev.shap_impact.toFixed(3)}
                              </span>
                            </div>
                          );
                        })}
                      </div>

                      {hasEncodedFeatures && (
                        <p className="obfuscation-note">
                          * Feature text was obfuscated by the data provider
                          for security.
                        </p>
                      )}
                    </div>
                  </article>
                );
              })}
          </div>
        </section>
      </main>
    </div>
  );
}

export default App;