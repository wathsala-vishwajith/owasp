import React, { useState } from 'react';
import axios from 'axios';
import './App.css';

const API_URL = 'http://localhost:8081/api';

function App() {
  const [results, setResults] = useState({});
  const [loading, setLoading] = useState({});

  const exploit = async (name, url, method = 'GET', data = null) => {
    setLoading(prev => ({ ...prev, [name]: true }));
    try {
      const response = await axios({ method, url: `${API_URL}${url}`, data });
      setResults(prev => ({ ...prev, [name]: response.data }));
    } catch (error) {
      setResults(prev => ({ ...prev, [name]: error.response?.data || error.message }));
    }
    setLoading(prev => ({ ...prev, [name]: false }));
  };

  return (
    <div className="app">
      <header className="header">
        <h1>🔧 OWASP A02: Security Misconfiguration</h1>
        <p className="warning">⚠️ Educational Demo - Intentionally Vulnerable!</p>
      </header>

      <div className="container">
        <section className="exploit-section">
          <h2>Exploitation Examples</h2>

          <div className="exploit-card">
            <h3>1. Exposed Secrets in Configuration</h3>
            <p>Application exposes API keys and secrets via endpoint</p>
            <button onClick={() => exploit('config', '/config')} disabled={loading.config}>
              Get Configuration
            </button>
            {results.config && <pre>{JSON.stringify(results.config, null, 2)}</pre>}
          </div>

          <div className="exploit-card">
            <h3>2. Verbose Error Messages</h3>
            <p>Trigger error to see stack trace and system information</p>
            <button onClick={() => exploit('error', '/trigger-error')} disabled={loading.error}>
              Trigger Error
            </button>
            {results.error && <pre>{JSON.stringify(results.error, null, 2)}</pre>}
          </div>

          <div className="exploit-card">
            <h3>3. Debug Endpoint Exposed</h3>
            <p>Access debug endpoint showing system information</p>
            <button onClick={() => exploit('debug', '/debug/system-info')} disabled={loading.debug}>
              Get System Info
            </button>
            {results.debug && <pre>{JSON.stringify(results.debug, null, 2)}</pre>}
          </div>

          <div className="exploit-card">
            <h3>4. Default Credentials</h3>
            <p>Login with admin/admin123 (default credentials)</p>
            <button
              onClick={() => exploit('login', '/login', 'POST', { username: 'admin', password: 'admin123' })}
              disabled={loading.login}
            >
              Login with Default Credentials
            </button>
            {results.login && <pre>{JSON.stringify(results.login, null, 2)}</pre>}
          </div>

          <div className="exploit-card">
            <h3>5. Actuator Endpoints (External Links)</h3>
            <p>Spring Actuator endpoints exposed without authentication:</p>
            <ul>
              <li><a href="http://localhost:8081/actuator" target="_blank" rel="noopener noreferrer">/actuator</a> - All endpoints</li>
              <li><a href="http://localhost:8081/actuator/env" target="_blank" rel="noopener noreferrer">/actuator/env</a> - Environment</li>
              <li><a href="http://localhost:8081/actuator/health" target="_blank" rel="noopener noreferrer">/actuator/health</a> - Health</li>
              <li><a href="http://localhost:8081/actuator/metrics" target="_blank" rel="noopener noreferrer">/actuator/metrics</a> - Metrics</li>
            </ul>
          </div>

          <div className="exploit-card">
            <h3>6. H2 Console Access</h3>
            <p>H2 Database console accessible without authentication:</p>
            <a href="http://localhost:8081/h2-console" target="_blank" rel="noopener noreferrer" className="link-button">
              Open H2 Console
            </a>
            <p className="note">JDBC URL: jdbc:h2:mem:misconfigdb</p>
          </div>
        </section>

        <section className="info-section">
          <h2>What's Wrong?</h2>
          <ul>
            <li>Debug mode enabled in production</li>
            <li>All actuator endpoints exposed without authentication</li>
            <li>H2 console accessible</li>
            <li>Secrets stored in configuration files</li>
            <li>Verbose error messages with stack traces</li>
            <li>Default credentials (admin/admin123)</li>
            <li>Missing security headers</li>
            <li>CORS allows all origins (*)</li>
            <li>Debug endpoints left in production</li>
          </ul>
        </section>
      </div>
    </div>
  );
}

export default App;
