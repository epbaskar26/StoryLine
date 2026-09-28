// AI provider for case summaries and the AI Storyline: Google Gemini (cloud) or Ollama (local, nothing
// leaves the machine). AI_PROVIDER picks one; by default Gemini if GEMINI_API_KEY is set, else Ollama if
// OLLAMA_URL is set, else none (deterministic output only).
import { GoogleGenAI } from '@google/genai';

export interface AiProvider {
  kind: 'gemini' | 'ollama' | 'claude';
  model: string;
  generate(system: string, prompt: string, opts?: { json?: boolean; temperature?: number; timeoutMs?: number }): Promise<string>;
}

function withTimeout<T>(p: Promise<T>, ms: number, label: string): Promise<T> {
  return Promise.race([p, new Promise<never>((_, reject) => setTimeout(() => reject(new Error(`${label} timed out after ${Math.round(ms / 1000)} s`)), ms))]);
}

function gemini(apiKey: string, model: string): AiProvider {
  const client = new GoogleGenAI({ apiKey });
  return {
    kind: 'gemini',
    model,
    async generate(system, prompt, opts = {}) {
      const call = client.models.generateContent({
        model,
        contents: prompt,
        config: { systemInstruction: system, temperature: opts.temperature ?? 0.2, ...(opts.json ? { responseMimeType: 'application/json' } : {}) },
      });
      const res = await withTimeout(call, opts.timeoutMs ?? 45000, 'Gemini request');
      return res.text || '';
    },
  };
}

function ollama(baseUrl: string, model: string): AiProvider {
  const url = baseUrl.replace(/\/+$/, '');
  return {
    kind: 'ollama',
    model,
    async generate(system, prompt, opts = {}) {
      const call = fetch(`${url}/api/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model,
          stream: false,
          ...(opts.json ? { format: 'json' } : {}),
          options: { temperature: opts.temperature ?? 0.2 },
          messages: [{ role: 'system', content: system }, { role: 'user', content: prompt }],
        }),
      }).then(async r => {
        const body = await r.text();
        if (!r.ok) throw new Error(`Ollama HTTP ${r.status}: ${body.slice(0, 200)}`);
        return JSON.parse(body)?.message?.content || '';
      });
      // Local models are slower; allow more time
      return withTimeout(call, opts.timeoutMs ?? 120000, 'Ollama request');
    },
  };
}

function claude(apiKey: string, model: string, baseUrl = 'https://api.anthropic.com'): AiProvider {
  const url = baseUrl.replace(/\/+$/, '');
  return {
    kind: 'claude',
    model,
    async generate(system, prompt, opts = {}) {
      // Anthropic has no native JSON response mode; nudge via system text and let parseJsonLoose handle it.
      const sys = opts.json ? `${system}\n\nRespond with a single valid JSON object and nothing else.` : system;
      const call = fetch(`${url}/v1/messages`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': apiKey,
          'anthropic-version': '2023-06-01',
        },
        body: JSON.stringify({
          model,
          max_tokens: 4096,
          temperature: opts.temperature ?? 0.2,
          system: sys,
          messages: [{ role: 'user', content: prompt }],
        }),
      }).then(async r => {
        const body = await r.text();
        if (!r.ok) throw new Error(`Claude HTTP ${r.status}: ${body.slice(0, 200)}`);
        const json = JSON.parse(body);
        // content is an array of blocks; concatenate the text blocks
        return (json?.content || []).filter((b: any) => b?.type === 'text').map((b: any) => b.text).join('') || '';
      });
      return withTimeout(call, opts.timeoutMs ?? 60000, 'Claude request');
    },
  };
}

export function loadAiProvider(env = process.env): AiProvider | null {
  const wanted = (env.AI_PROVIDER || '').toLowerCase();
  const geminiKey = env.GEMINI_API_KEY && env.GEMINI_API_KEY !== 'MY_GEMINI_API_KEY' ? env.GEMINI_API_KEY : '';
  const geminiModel = env.GEMINI_MODEL || 'gemini-3.8-flash';
  const ollamaUrl = env.OLLAMA_URL || '';
  const ollamaModel = env.OLLAMA_MODEL || 'llama3.1:8b';
  const claudeKey = env.ANTHROPIC_API_KEY && env.ANTHROPIC_API_KEY !== 'MY_ANTHROPIC_API_KEY' ? env.ANTHROPIC_API_KEY : '';
  const claudeModel = env.CLAUDE_MODEL || 'claude-sonnet-4-5';
  const claudeBase = env.ANTHROPIC_BASE_URL || 'https://api.anthropic.com';
  if (wanted === 'none') return null;
  if (wanted === 'gemini') {
    if (!geminiKey) throw new Error('AI_PROVIDER=gemini requires GEMINI_API_KEY');
    return gemini(geminiKey, geminiModel);
  }
  if (wanted === 'claude') {
    if (!claudeKey) throw new Error('AI_PROVIDER=claude requires ANTHROPIC_API_KEY');
    return claude(claudeKey, claudeModel, claudeBase);
  }
  if (wanted === 'ollama') return ollama(ollamaUrl || 'http://127.0.0.1:11434', ollamaModel);
  if (wanted) throw new Error(`Unknown AI_PROVIDER "${wanted}" (use gemini, claude, ollama or none)`);
  // Auto-detect when AI_PROVIDER is unset: Gemini, then Claude, then Ollama.
  if (geminiKey) return gemini(geminiKey, geminiModel);
  if (claudeKey) return claude(claudeKey, claudeModel, claudeBase);
  if (ollamaUrl) return ollama(ollamaUrl, ollamaModel);
  return null;
}

// Models sometimes wrap JSON in code fences or add prose around it
export function parseJsonLoose(text: string): any {
  const t = text.trim().replace(/^```(?:json)?\s*/i, '').replace(/```\s*$/, '');
  try {
    return JSON.parse(t);
  } catch {
    const start = t.indexOf('{');
    const end = t.lastIndexOf('}');
    if (start >= 0 && end > start) return JSON.parse(t.slice(start, end + 1));
    throw new Error('The model did not return JSON');
  }
}
