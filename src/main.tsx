import { StrictMode, useState } from 'react';
import { createRoot } from 'react-dom/client';
import App from './App.tsx';
import { LoginScreen } from './components/LoginScreen';
import './index.css';

const AUTH_KEY = 'watchme-authed';

function readAuthed(): boolean {
  try {
    return localStorage.getItem(AUTH_KEY) === '1';
  } catch {
    return false;
  }
}

/**
 * Demo auth gate. This is NOT real authentication — it only toggles a local
 * flag so the demo has a front door. WatchMe itself has no server-side auth.
 */
function Root() {
  const [authed, setAuthed] = useState<boolean>(readAuthed);

  const signIn = () => {
    try { localStorage.setItem(AUTH_KEY, '1'); } catch { /* storage unavailable */ }
    setAuthed(true);
  };
  const signOut = () => {
    try { localStorage.removeItem(AUTH_KEY); } catch { /* storage unavailable */ }
    setAuthed(false);
  };

  return authed ? <App onSignOut={signOut} /> : <LoginScreen onSignIn={signIn} />;
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <Root />
  </StrictMode>,
);
