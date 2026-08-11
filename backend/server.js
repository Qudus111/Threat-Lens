require('dotenv').config();
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const crypto = require('crypto');
const axios = require('axios');
const FormData = require('form-data');

const app = express();
const PORT = process.env.PORT || 3000;
const API_KEY = process.env.VIRUSTOTAL_API_KEY;
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
const GEMINI_MODEL = 'gemini-3.5-flash'; // free tier — change here if Google renames/retires it later

// Free VirusTotal accounts: 32MB max file size, ~4 requests/minute
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 32 * 1024 * 1024 } });

app.use(cors()); // allows your frontend (running on a different port) to call this backend
app.use(express.json());

const COACH_SYSTEM_PROMPT = `You are the ThreatLens AI Coach, a friendly cybersecurity awareness mentor built into a security dashboard app.
Your job is to teach everyday users about cybersecurity, with special emphasis on the CIA triad (Confidentiality, Integrity, Availability) whenever it's relevant.
Keep answers clear, practical, and beginner-friendly — this is not an audience of security professionals.
Keep responses fairly short (a few sentences to a short list) unless the user asks for more depth.
If asked something unrelated to cybersecurity/security awareness, gently steer back to what you're here to help with.
Never provide guidance that would help someone attack, exploit, or compromise a real system — only defensive, educational content.`;

app.post('/api/coach', async (req, res) => {
  if (!GEMINI_API_KEY) {
    return res.status(500).json({ error: 'Server is missing GEMINI_API_KEY. Check your .env file.' });
  }
  const { messages } = req.body;
  if (!Array.isArray(messages) || !messages.length) {
    return res.status(400).json({ error: 'No conversation messages were provided.' });
  }

  // Convert our {role: 'user'|'assistant', content} history into Gemini's {role: 'user'|'model', parts} shape
  const contents = messages.map(m => ({
    role: m.role === 'assistant' ? 'model' : 'user',
    parts: [{ text: m.content }],
  }));

  try {
    const response = await axios.post(
      `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent`,
      {
        contents,
        systemInstruction: { parts: [{ text: COACH_SYSTEM_PROMPT }] },
      },
      {
        headers: {
          'x-goog-api-key': GEMINI_API_KEY,
          'Content-Type': 'application/json',
        },
      }
    );

    const reply = response.data.candidates?.[0]?.content?.parts?.map(p => p.text).join('\n') || '';
    if (!reply) throw new Error('No reply returned from Gemini.');

    res.json({ reply });
  } catch (err) {
    console.error(err.response?.data || err.message);
    res.status(500).json({ error: 'AI Coach request failed. Check the server logs for details.' });
  }
});

const VT_BASE = 'https://www.virustotal.com/api/v3';

function vtHeaders() {
  return { 'x-apikey': API_KEY };
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

app.post('/api/scan', upload.single('file'), async (req, res) => {
  if (!API_KEY) {
    return res.status(500).json({ error: 'Server is missing VIRUSTOTAL_API_KEY. Check your .env file.' });
  }
  if (!req.file) {
    return res.status(400).json({ error: 'No file was uploaded.' });
  }

  const { buffer, originalname } = req.file;
  const sha256 = crypto.createHash('sha256').update(buffer).digest('hex');

  try {
    // 1. Check if VirusTotal already has a report for this exact file (by hash)
    try {
      const existing = await axios.get(`${VT_BASE}/files/${sha256}`, { headers: vtHeaders() });
      return res.json(buildResult(originalname, sha256, existing.data.data.attributes.last_analysis_stats, true));
    } catch (err) {
      if (!err.response || err.response.status !== 404) throw err;
      // 404 just means "not seen before" — fall through to upload it
    }

    // 2. Upload the file for a fresh scan
    const form = new FormData();
    form.append('file', buffer, originalname);
    const uploadRes = await axios.post(`${VT_BASE}/files`, form, {
      headers: { ...vtHeaders(), ...form.getHeaders() },
      maxBodyLength: Infinity,
    });
    const analysisId = uploadRes.data.data.id;

    // 3. Poll until the analysis finishes (VirusTotal scans asynchronously)
    let stats = null;
    for (let attempt = 0; attempt < 15; attempt++) {
      await sleep(2000);
      const analysis = await axios.get(`${VT_BASE}/analyses/${analysisId}`, { headers: vtHeaders() });
      const status = analysis.data.data.attributes.status;
      if (status === 'completed') {
        stats = analysis.data.data.attributes.stats;
        break;
      }
    }

    if (!stats) {
      return res.status(202).json({ error: 'Scan is taking longer than expected. Try again shortly — VirusTotal is still analyzing this file.' });
    }

    res.json(buildResult(originalname, sha256, stats, false));
  } catch (err) {
    console.error(err.response?.data || err.message);
    res.status(500).json({ error: 'Scan failed. Check the server logs for details.' });
  }
});

function buildResult(fileName, sha256, stats, cached) {
  const malicious = stats.malicious || 0;
  const suspicious = stats.suspicious || 0;
  const harmless = stats.harmless || 0;
  const undetected = stats.undetected || 0;
  const isThreat = malicious > 0 || suspicious > 0;

  return {
    fileName,
    sha256,
    cached,
    isThreat,
    stats: { malicious, suspicious, harmless, undetected },
    permalink: `https://www.virustotal.com/gui/file/${sha256}`,
  };
}

app.get('/api/health', (req, res) => res.json({ ok: true }));

app.listen(PORT, () => {
  console.log(`ThreatLens backend running at http://localhost:${PORT}`);
});
