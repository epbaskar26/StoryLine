import React, { useState } from 'react';
import { Shield, LogIn, Lock } from 'lucide-react';

interface Props {
  onSignIn: () => void;
}

/**
 * A DEMO sign-in gate. It performs NO real authentication: clicking "Sign in"
 * (with any values, or none) simply flips a local flag and drops you into the
 * tool. It exists only to give the local demo a realistic front door. Do not
 * mistake it for an access control — WatchMe binds to 127.0.0.1 and has no
 * server-side auth by design.
 */
export const LoginScreen: React.FC<Props> = ({ onSignIn }) => {
  const [username, setUsername] = useState('analyst');
  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    onSignIn();
  };

  return (
    <div className="w-screen h-screen flex items-center justify-center bg-slate-950 text-slate-100 font-sans px-4">
      <div className="w-full max-w-sm">
        <div className="flex flex-col items-center mb-8">
          <img src="/storyline-logo.png" alt="StoryLine" className="w-72 max-w-full h-auto rounded-2xl bg-white p-3 shadow-lg" />
        </div>

        <form
          onSubmit={submit}
          data-testid="login-form"
          className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-4 shadow-2xl"
        >
          <label className="block space-y-1">
            <span className="text-xs font-mono text-slate-400">Username</span>
            <input
              data-testid="login-username"
              type="text"
              value={username}
              onChange={e => setUsername(e.target.value)}
              autoFocus
              className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-100 focus:outline-none focus:ring-1 focus:ring-cyan-500"
            />
          </label>
          <label className="block space-y-1">
            <span className="text-xs font-mono text-slate-400">Password</span>
            <input
              data-testid="login-password"
              type="password"
              placeholder="not checked (demo)"
              className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-100 focus:outline-none focus:ring-1 focus:ring-cyan-500"
            />
          </label>

          <button
            data-testid="login-submit"
            type="submit"
            className="w-full flex items-center justify-center gap-2 px-4 py-2.5 bg-cyan-600 hover:bg-cyan-500 text-white font-semibold rounded-lg transition-colors"
          >
            <LogIn className="w-4 h-4" /> Sign in
          </button>

          <div className="flex items-start gap-2 text-[11px] text-amber-300/90 bg-amber-500/10 border border-amber-500/30 rounded-lg px-3 py-2">
            <Lock className="w-3.5 h-3.5 shrink-0 mt-0.5" />
            <span>
              Demo sign-in only — credentials are <strong>not</strong> verified. Any click signs you in.
              StoryLine runs locally with no real authentication.
            </span>
          </div>
        </form>
      </div>
    </div>
  );
};
