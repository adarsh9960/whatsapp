// api/flow.js - Vercel serverless wrapper for WhatsApp Flow encryption endpoint
import fs from "fs";
import path from "path";
import { decryptRequest, encryptResponse } from "../src/encryption.js"; // expects existing functions in src/encryption.js
import flowLogic from "../src/flow.js"; // expects an exported function to handle decrypted body

export default async function handler(req, res) {
  // Basic health check
  if (req.method === 'GET') {
    const challenge = req.query.challenge || null;
    if (challenge) {
      // Sign the challenge using PRIVATE_KEY from env
      const privateKey = process.env.PRIVATE_KEY || '';
      if (!privateKey) {
        return res.status(500).json({ error: 'Private key not configured' });
      }
      try {
        const sign = require('crypto').sign('sha256', Buffer.from(challenge), {
          key: privateKey,
          padding: require('crypto').constants.RSA_PKCS1_PADDING
        });
        const signature = sign.toString('base64');
        return res.status(200).json({ status: 'ok', challenge, signature });
      } catch (e) {
        return res.status(500).json({ error: 'Signing failed', detail: e.message });
      }
    }
    return res.status(200).json({ status: 'ok', message: 'Endpoint alive' });
  }

  // Handle POST - expecting encrypted payload from Meta
  if (req.method === 'POST') {
    try {
      // If encryption functions exist, attempt to decrypt, otherwise return 400
      const body = req.body || {};
      if (Object.keys(body).length === 0) {
        return res.status(400).json({ ok:false, error:'Empty request body' });
      }
      const privateKey = process.env.PRIVATE_KEY || '';
      if (!privateKey) return res.status(500).json({ ok:false, error:'Private key not configured' });

      // Use decryptRequest from src/encryption.js
      if (typeof decryptRequest === 'function') {
        const decrypted = await decryptRequest(body, privateKey);
        // flowLogic should process decrypted and return response object
        let reply = {};
        if (typeof flowLogic === 'function') {
          reply = await flowLogic(decrypted);
        } else {
          reply = { status:'ok', received: decrypted };
        }
        // Encrypt response using encryptResponse
        if (typeof encryptResponse === 'function') {
          const encrypted = await encryptResponse(reply, body, privateKey);
          // Return raw encrypted string (Meta expects text/plain ciphertext)
          res.setHeader('Content-Type','text/plain');
          return res.status(200).send(encrypted);
        } else {
          return res.status(200).json({ ok:true, reply });
        }
      } else {
        return res.status(500).json({ ok:false, error:'decryptRequest not implemented in src/encryption.js' });
      }
    } catch (err) {
      return res.status(500).json({ ok:false, error: err.message });
    }
  }

  res.setHeader('Allow', 'GET, POST');
  return res.status(405).end();
}
