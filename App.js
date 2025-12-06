import React, { useState, useEffect } from 'react';
import { Shield, Lock, Key, Users, AlertTriangle, CheckCircle, Database, LogOut } from 'lucide-react';

const API_BASE = 'http://localhost:4000';

const sanitizeInput = (input) => {
  const d = document.createElement('div');
  d.textContent = input;
  return d.innerHTML;
};

const decodeJwtPayload = (token) => {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    return JSON.parse(atob(parts[1]));
  } catch {
    return null;
  }
};

const SecureWebApp = () => {
  const [activeTab, setActiveTab] = useState('login');
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(localStorage.getItem('token') || null);
  const [securityLogs, setSecurityLogs] = useState([]);

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [regName, setRegName] = useState('');
  const [regEmail, setRegEmail] = useState('');
  const [regPassword, setRegPassword] = useState('');

  const [dataTitle, setDataTitle] = useState('');
  const [dataContent, setDataContent] = useState('');
  const [vault, setVault] = useState([]);

  const addLog = (type, message) => {
    setSecurityLogs(prev => [{ type, message, timestamp: new Date().toLocaleTimeString() }, ...prev].slice(0, 20));
  };

  const authHeaders = () => ({ Authorization: `Bearer ${localStorage.getItem('token')}` });

  // Check for Google SSO callback
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const ssoToken = params.get('token');
    const ssoEmail = params.get('email');
    const ssoName = params.get('name');
    
    if (ssoToken) {
      localStorage.setItem('token', ssoToken);
      setToken(ssoToken);
      const payload = decodeJwtPayload(ssoToken);
      setUser({ 
        id: payload?.sub, 
        email: decodeURIComponent(ssoEmail), 
        name: decodeURIComponent(ssoName) 
      });
      setActiveTab('dashboard');
      addLog('success', `✅ Google SSO login successful: ${decodeURIComponent(ssoEmail)}`);
      
      window.history.replaceState({}, document.title, window.location.pathname);
      loadVault();
    }
  }, []);

  const handleRegister = async () => {
    if (!regEmail || !regPassword || regPassword.length < 8) {
      addLog('error', 'Invalid registration input');
      return;
    }
    try {
      const res = await fetch(`${API_BASE}/api/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: sanitizeInput(regName),
          email: sanitizeInput(regEmail),
          password: regPassword
        })
      });
      if (res.status === 201) {
        addLog('success', 'Registered successfully. Please login.');
        setActiveTab('login');
        setRegEmail(''); setRegPassword(''); setRegName('');
      } else {
        const body = await res.json();
        addLog('error', `Register failed: ${body.error || res.statusText}`);
      }
    } catch (e) {
      addLog('error', 'Register request failed');
    }
  };

  const handleLogin = async () => {
    if (!email || !password) { addLog('error','Missing credentials'); return; }
    try {
      const res = await fetch(`${API_BASE}/api/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: sanitizeInput(email), password })
      });
      if (!res.ok) {
        const b = await res.json().catch(()=>({})); 
        if (b.error === 'use_google_sso') {
          addLog('error', 'This account uses Google SSO. Please sign in with Google.');
        } else {
          addLog('error', `Login failed: ${b.error || res.statusText}`);
        }
        return;
      }
      const { token: jwt } = await res.json();
      localStorage.setItem('token', jwt);
      setToken(jwt);
      const payload = decodeJwtPayload(jwt);
      setUser({ id: payload?.sub, email: payload?.email, name: payload?.name || payload?.email });
      setActiveTab('dashboard');
      addLog('success', `Logged in: ${payload?.email}`);
      setEmail(''); setPassword('');
      await loadVault();
    } catch (e) {
      addLog('error', 'Login request failed');
    }
  };

  const handleGoogleSSO = () => {
    addLog('info', 'Redirecting to Google SSO...');
    window.location.href = `${API_BASE}/auth/google`;
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    setToken(null);
    setUser(null);
    setVault([]);
    setActiveTab('login');
    addLog('info', 'Logged out');
  };

  const addSensitiveData = async () => {
    if (!token) { addLog('error','Not authenticated'); return; }
    if (!dataTitle.trim() || !dataContent.trim()) { addLog('error','Empty title or content'); return; }
    try {
      const res = await fetch(`${API_BASE}/api/data`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...authHeaders() },
        body: JSON.stringify({ title: sanitizeInput(dataTitle), content: sanitizeInput(dataContent) })
      });
      if (res.ok) {
        addLog('success', 'Encrypted data stored on server');
        setDataTitle(''); setDataContent('');
        await loadVault();
      } else {
        const b = await res.json().catch(()=>({})); addLog('error', `Store failed: ${b.error || res.statusText}`);
      }
    } catch {
      addLog('error', 'Store request failed');
    }
  };

  const loadVault = async () => {
    if (!token) return;
    try {
      const res = await fetch(`${API_BASE}/api/data`, { headers: authHeaders() });
      if (res.ok) {
        const list = await res.json();
        setVault(list);
      } else {
        addLog('error', 'Failed to load vault');
      }
    } catch {
      addLog('error', 'Vault request failed');
    }
  };

  const decryptAndView = async (itemId) => {
    if (!token) { addLog('error','Not authenticated'); return; }
    try {
      const res = await fetch(`${API_BASE}/api/data/${encodeURIComponent(itemId)}/decrypt`, {
        method: 'POST',
        headers: authHeaders()
      });
      if (res.ok) {
        const { data } = await res.json();
        alert(`Title: ${data.title}\n\nContent: ${data.content}`);
        addLog('info', `Decrypted: ${data.title}`);
      } else {
        const b = await res.json().catch(()=>({})); addLog('error', `Decrypt failed: ${b.error || res.statusText}`);
      }
    } catch {
      addLog('error', 'Decrypt request failed');
    }
  };

  useEffect(() => {
    if (token && !user) {
      const payload = decodeJwtPayload(token);
      if (payload) setUser({ id: payload.sub, email: payload.email, name: payload.name || payload.email });
    }
    if (token) loadVault();
  }, [token]);

  return (
    <div style={{ fontFamily:'Inter, system-ui, Arial', background:'#0b1220', minHeight:'100vh', color:'#fff', padding:20 }}>
      <div style={{ maxWidth:1100, margin:'0 auto' }}>
        <header style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:20 }}>
          <div style={{ display:'flex', alignItems:'center', gap:12 }}>
            <div style={{ background:'#0ea5e9', padding:12, borderRadius:12 }}><Shield/></div>
            <div>
              <h1 style={{ margin:0 }}>SecureVault</h1>
              <small style={{ color:'#9ca3af' }}>AES / bcrypt / JWT / Google SSO</small>
            </div>
          </div>
          <div>
            {user ? (
              <div style={{ display:'flex', alignItems:'center', gap:12 }}>
                <div style={{ textAlign:'right' }}>
                  <div>{user.name}</div>
                  <small style={{ color:'#9ca3af' }}>{user.email}</small>
                </div>
                <button onClick={handleLogout} style={{ marginLeft:12, background:'#ef4444', border:0, color:'#fff', padding:'8px 12px', borderRadius:8, cursor:'pointer' }}>
                  <LogOut style={{ verticalAlign:'middle' }}/> Logout
                </button>
              </div>
            ) : null}
          </div>
        </header>

        <main style={{ display:'grid', gridTemplateColumns:'2fr 1fr', gap:20 }}>
          <section style={{ background:'#071026', padding:20, borderRadius:12 }}>
            {!user && (
              <div>
                <div style={{ display:'flex', gap:8, marginBottom:16 }}>
                  <button onClick={()=>setActiveTab('login')} style={{ flex:1, padding:10, background: activeTab==='login' ? '#0ea5e9' : '#0f1724', border:0, borderRadius:8, color:'#fff', cursor:'pointer' }}>Login</button>
                  <button onClick={()=>setActiveTab('register')} style={{ flex:1, padding:10, background: activeTab==='register' ? '#8b5cf6' : '#0f1724', border:0, borderRadius:8, color:'#fff', cursor:'pointer' }}>Register</button>
                </div>
                {activeTab === 'login' && (
                  <div>
                    <input placeholder="Email" value={email} onChange={e=>setEmail(e.target.value)} style={{ width:'100%', padding:10, marginBottom:8, borderRadius:8, border:0 }} />
                    <input placeholder="Password" type="password" value={password} onChange={e=>setPassword(e.target.value)} style={{ width:'100%', padding:10, marginBottom:8, borderRadius:8, border:0 }} />
                    <button onClick={handleLogin} style={{ width:'100%', padding:12, background:'#06b6d4', border:0, borderRadius:8, color:'#fff', fontWeight:'bold', cursor:'pointer', marginBottom:12 }}>Sign in</button>
                    
                    <div style={{ textAlign:'center', margin:'20px 0', color:'#6b7280' }}>— OR —</div>
                    
                    <button onClick={handleGoogleSSO} style={{ width:'100%', padding:12, background:'#fff', border:'1px solid #ddd', borderRadius:8, color:'#000', fontWeight:'bold', cursor:'pointer', display:'flex', alignItems:'center', justifyContent:'center', gap:8 }}>
                      <svg width="18" height="18" viewBox="0 0 18 18">
                        <path fill="#4285F4" d="M17.64 9.2c0-.637-.057-1.251-.164-1.84H9v3.481h4.844c-.209 1.125-.843 2.078-1.796 2.717v2.258h2.908c1.702-1.567 2.684-3.874 2.684-6.615z"/>
                        <path fill="#34A853" d="M9 18c2.43 0 4.467-.806 5.956-2.180l-2.908-2.259c-.806.54-1.837.86-3.048.86-2.344 0-4.328-1.584-5.036-3.711H.957v2.332C2.438 15.983 5.482 18 9 18z"/>
                        <path fill="#FBBC05" d="M3.964 10.71c-.18-.54-.282-1.117-.282-1.71s.102-1.17.282-1.71V4.958H.957C.347 6.173 0 7.548 0 9s.348 2.827.957 4.042l3.007-2.332z"/>
                        <path fill="#EA4335" d="M9 3.58c1.321 0 2.508.454 3.440 1.345l2.582-2.58C13.463.891 11.426 0 9 0 5.482 0 2.438 2.017.957 4.958L3.964 7.29C4.672 5.163 6.656 3.58 9 3.58z"/>
                      </svg>
                      Sign in with Google
                    </button>
                  </div>
                )}
                {activeTab === 'register' && (
                  <div>
                    <input placeholder="Full name" value={regName} onChange={e=>setRegName(e.target.value)} style={{ width:'100%', padding:10, marginBottom:8, borderRadius:8, border:0 }} />
                    <input placeholder="Email" value={regEmail} onChange={e=>setRegEmail(e.target.value)} style={{ width:'100%', padding:10, marginBottom:8, borderRadius:8, border:0 }} />
                    <input placeholder="Password (min 8)" type="password" value={regPassword} onChange={e=>setRegPassword(e.target.value)} style={{ width:'100%', padding:10, marginBottom:8, borderRadius:8, border:0 }} />
                    <button onClick={handleRegister} style={{ width:'100%', padding:12, background:'#8b5cf6', border:0, borderRadius:8, color:'#fff', fontWeight:'bold', cursor:'pointer' }}>Create account</button>
                  </div>
                )}
              </div>
            )}

            {user && (
              <div>
                <h2>Encrypted Data Vault</h2>
                <div style={{ background:'#071226', padding:12, borderRadius:8, marginBottom:12 }}>
                  <input placeholder="Title" value={dataTitle} onChange={e=>setDataTitle(e.target.value)} style={{ width:'100%', padding:10, marginBottom:8, borderRadius:8, border:0 }} />
                  <textarea placeholder="Sensitive content" value={dataContent} onChange={e=>setDataContent(e.target.value)} rows={4} style={{ width:'100%', padding:10, marginBottom:8, borderRadius:8, border:0 }} />
                  <button onClick={addSensitiveData} style={{ padding:12, background:'#10b981', border:0, borderRadius:8, color:'#fff', fontWeight:'bold', cursor:'pointer' }}>Encrypt & Store</button>
                </div>

                <div>
                  <h3>Stored (encrypted)</h3>
                  {vault.length === 0 && <div style={{ color:'#9ca3af' }}>No stored items</div>}
                  {vault.map(item => (
                    <div key={item.id} style={{ background:'#061126', padding:12, borderRadius:8, marginBottom:8, display:'flex', justifyContent:'space-between', alignItems:'center' }}>
                      <div>
                        <div style={{ fontWeight:600 }}>{item.id}</div>
                        <div style={{ color:'#9ca3af', fontSize:12 }}>iv: {item.iv?.slice(0,12)}...</div>
                      </div>
                      <div>
                        <button onClick={()=>decryptAndView(item.id)} style={{ padding:'6px 10px', background:'#06b6d4', border:0, borderRadius:8, color:'#fff', cursor:'pointer' }}>Decrypt</button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </section>

          <aside style={{ background:'#071026', padding:20, borderRadius:12 }}>
            <h3 style={{ marginTop:0 }}>Security Logs</h3>
            <div style={{ maxHeight:500, overflow:'auto' }}>
              {securityLogs.length === 0 && <div style={{ color:'#9ca3af' }}>No events yet</div>}
              {securityLogs.map((log, i)=>(
                <div key={i} style={{ padding:8, marginBottom:8, background: log.type==='success' ? '#052e14' : log.type==='error' ? '#2a0b0b' : '#07203a', borderRadius:8 }}>
                  <div style={{ fontSize:13, color: log.type==='success' ? '#86efac' : log.type==='error' ? '#fca5a5' : '#93c5fd' }}>{log.message}</div>
                  <div style={{ fontSize:11, color:'#9ca3af' }}>{log.timestamp}</div>
                </div>
              ))}
            </div>
          </aside>
        </main>
      </div>
    </div>
  );
};

export default SecureWebApp;