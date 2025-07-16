const express = require('express');
const axios = require('axios');
const dns = require('dns').promises;
const path = require('path');
const app = express();
const PORT = process.env.PORT || 3000;

// Support JSON body parsing
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Trust proxy headers if behind load balancer
app.set('trust proxy', true);

// Middleware for comprehensive IP detection
app.use(async (req, res, next) => {
  // Store all IP information in req object
  req.ipInfo = {
    // Basic connection info
    connection: {
      direct: req.socket.remoteAddress,
      port: req.socket.remotePort,
      encrypted: !!req.socket.encrypted,
      protocol: req.protocol,
    },
    
    // Header-based detection
    headers: {
      xForwardedFor: req.headers['x-forwarded-for'],
      xRealIp: req.headers['x-real-ip'],
      cfConnectingIp: req.headers['cf-connecting-ip'],
      trueClientIp: req.headers['true-client-ip'],
      forwarded: req.headers['forwarded'],
    },
    
    // Express built-in detection
    express: {
      ip: req.ip,
      ips: req.ips,
    },
    
    // Custom detection
    detected: {
      ipv4: null,
      ipv6: null,
      isIPv4MappedIPv6: false,
      source: null,
    }
  };
  
  // Extract IPv4 from IPv4-mapped IPv6 if present
  const ip = req.socket.remoteAddress;
  if (ip && ip.includes(':')) {
    req.ipInfo.detected.ipv6 = ip;
    
    if (ip.startsWith('::ffff:')) {
      const ipv4 = ip.substring(7);
      req.ipInfo.detected.ipv4 = ipv4;
      req.ipInfo.detected.isIPv4MappedIPv6 = true;
      req.ipInfo.detected.source = 'ipv4-mapped-ipv6';
    }
  } else if (ip && /^\d+\.\d+\.\d+\.\d+$/.test(ip)) {
    req.ipInfo.detected.ipv4 = ip;
    req.ipInfo.detected.source = 'direct-connection';
  }
  
  // Check headers for IPv4 if not found yet
  if (!req.ipInfo.detected.ipv4) {
    // Try X-Forwarded-For
    const xForwardedFor = req.headers['x-forwarded-for'];
    if (xForwardedFor) {
      const ips = xForwardedFor.split(',').map(ip => ip.trim());
      for (const headerIp of ips) {
        if (/^\d+\.\d+\.\d+\.\d+$/.test(headerIp)) {
          req.ipInfo.detected.ipv4 = headerIp;
          req.ipInfo.detected.source = 'x-forwarded-for';
          break;
        }
      }
    }
    
    // Try other headers if still not found
    if (!req.ipInfo.detected.ipv4) {
      const headersToCheck = [
        { name: 'x-real-ip', value: req.headers['x-real-ip'] },
        { name: 'cf-connecting-ip', value: req.headers['cf-connecting-ip'] },
        { name: 'true-client-ip', value: req.headers['true-client-ip'] }
      ];
      
      for (const header of headersToCheck) {
        if (header.value && /^\d+\.\d+\.\d+\.\d+$/.test(header.value)) {
          req.ipInfo.detected.ipv4 = header.value;
          req.ipInfo.detected.source = header.name;
          break;
        }
      }
    }
  }
  
  next();
});

// Route 1: HTML Response (homepage)
app.get('/', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>IP Address Detector</title>
      <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
        h1 { color: #333; }
        .ip-box { background: #f4f4f4; padding: 15px; border-radius: 5px; margin: 15px 0; }
        .ip-box h2 { margin-top: 0; }
        pre { background: #eee; padding: 10px; overflow: auto; }
        .footer { margin-top: 30px; font-size: 12px; color: #666; }
        .ip-list { background: #f4f4f4; padding: 15px; border-radius: 5px; margin: 15px 0; }
        .ip-list ul { list-style: none; padding: 0; }
        .ip-list li { padding: 5px 0; }
        .note { color: #b00; font-size: 13px; margin-top: 10px; }
      </style>
    </head>
    <body>
      <h1>IP Address Detector</h1>
      <div class="ip-box">
        <h2>Your IP Addresses (Server-side)</h2>
        <p><strong>IPv4:</strong> ${req.ipInfo.detected.ipv4 || 'Not detected'}</p>
        <p><strong>IPv6:</strong> ${req.ipInfo.detected.ipv6 || 'Not detected'}</p>
        <p><strong>Detection source:</strong> ${req.ipInfo.detected.source || 'Unknown'}</p>
      </div>
      <div class="ip-box">
        <h2>Raw Connection Data</h2>
        <p><strong>Direct connection IP:</strong> ${req.ipInfo.connection.direct}</p>
        <p><strong>Protocol:</strong> ${req.ipInfo.connection.protocol}</p>
        <p><strong>Port:</strong> ${req.ipInfo.connection.port}</p>
      </div>
      <div class="ip-box">
        <h2>Express Detection</h2>
        <p><strong>req.ip:</strong> ${req.ip}</p>
        <p><strong>req.ips:</strong> ${JSON.stringify(req.ips)}</p>
      </div>
      <div class="ip-box">
        <h2>Header Information</h2>
        <pre>${JSON.stringify(req.headers, null, 2)}</pre>
      </div>
      <div class="ip-box">
        <h2>API Endpoints</h2>
        <p>Get as JSON: <a href="/api/ip">/api/ip</a></p>
        <p>Get as plain text: <a href="/api/ip/text">/api/ip/text</a></p>
        <p>Get full details: <a href="/api/ip/details">/api/ip/details</a></p>
        <p>External verification: <a href="/api/ip/verify">/api/ip/verify</a></p>
        <p>WebRTC IP detection: <a href="/webrtc">/webrtc</a></p>
      </div>
      <div class="ip-list">
        <h2>Your Public IP Addresses (via WebRTC STUN):</h2>
        <ul id="ip-list">
          <li>Detecting...</li>
        </ul>
        <div class="note" id="note"></div>
      </div>
      <div class="footer">
        <p>Server Time (UTC): ${new Date().toISOString()}</p>
        <p>Request ID: ${Math.random().toString(36).substring(2, 15)}</p>
      </div>
      <script>
        function isIpAddress(ip) {
          // IPv4 or IPv6 regex
          return /^([0-9]{1,3}\.){3}[0-9]{1,3}$/.test(ip) || /^[a-fA-F0-9:]+$/.test(ip);
        }
        function getWebRTCIpsWithStun(callback) {
          const ips = new Set();
          const RTCPeerConnection = window.RTCPeerConnection || window.mozRTCPeerConnection || window.webkitRTCPeerConnection;
          if (!RTCPeerConnection) {
            callback(['WebRTC not supported']);
            return;
          }
          const stunServers = [
            { urls: 'stun:stun.l.google.com:19302' },
            { urls: 'stun:stun.cloudflare.com:3478' }
          ];
          let pending = stunServers.length;
          stunServers.forEach(server => {
            const pc = new RTCPeerConnection({ iceServers: [server] });
            pc.createDataChannel('');
            pc.createOffer().then(offer => pc.setLocalDescription(offer));
            pc.onicecandidate = function(event) {
              if (!event || !event.candidate) {
                pending--;
                if (pending === 0) {
                  callback(Array.from(ips));
                }
                return;
              }
              const candidate = event.candidate.candidate;
              const parts = candidate.split(' ');
              const ip = parts[4];
              if (ip && isIpAddress(ip) && !ips.has(ip)) {
                ips.add(ip);
              }
            };
          });
        }
        getWebRTCIpsWithStun(function(ipList) {
          const ul = document.getElementById('ip-list');
          const note = document.getElementById('note');
          ul.innerHTML = '';
          if (ipList.length === 0) {
            ul.innerHTML = '<li>No public IPs detected</li>';
            note.textContent = 'Modern browsers may hide your real IPs for privacy (mDNS obfuscation).';
          } else {
            let realIps = ipList.filter(ip => !ip.endsWith('.local'));
            if (realIps.length === 0) {
              ul.innerHTML = '<li>Only mDNS hostnames detected (no real IPs)</li>';
              note.textContent = 'Your browser is hiding your real IPs for privacy (mDNS obfuscation).';
            } else {
              realIps.forEach(ip => {
                const li = document.createElement('li');
                li.textContent = ip;
                ul.appendChild(li);
              });
              if (realIps.length < ipList.length) {
                note.textContent = 'Some IPs are hidden by your browser for privacy.';
              } else {
                note.textContent = '';
              }
            }
          }
        });
      </script>
    </body>
    </html>
  `);
});

// Route 2: JSON API
app.get('/api/ip', (req, res) => {
  res.json({
    ipv4: req.ipInfo.detected.ipv4,
    ipv6: req.ipInfo.detected.ipv6,
    source: req.ipInfo.detected.source,
    timestamp: new Date().toISOString()
  });
});

// Route 3: Plain text (just the IP)
app.get('/api/ip/text', (req, res) => {
  res.setHeader('Content-Type', 'text/plain');
  res.send(req.ipInfo.detected.ipv4 || req.ipInfo.detected.ipv6 || 'No IP detected');
});

// Route 4: Detailed JSON
app.get('/api/ip/details', (req, res) => {
  res.json({
    result: 'success',
    timestamp: new Date().toISOString(),
    ip_info: req.ipInfo,
    request: {
      method: req.method,
      url: req.url,
      path: req.path,
      protocol: req.protocol,
      secure: req.secure,
      user_agent: req.headers['user-agent']
    }
  });
});

// Route 5: External verification
app.get('/api/ip/verify', async (req, res) => {
  try {
    const services = [
      { name: 'ipv4.jsonip.com', url: 'https://ipv4.jsonip.com/' },
      { name: 'ipify', url: 'https://api.ipify.org?format=json' }
    ];
    
    const results = await Promise.allSettled(
      services.map(service => 
        axios.get(service.url, { timeout: 5000 })
          .then(response => ({ 
            service: service.name, 
            success: true, 
            ip: response.data.ip,
            raw: response.data
          }))
          .catch(error => ({ 
            service: service.name, 
            success: false, 
            error: error.message 
          }))
      )
    );
    
    // DNS lookup attempt if we have a hostname
    let dnsResult = null;
    if (req.ipInfo.detected.ipv6) {
      try {
        const hostnames = await dns.reverse(req.ipInfo.detected.ipv6);
        if (hostnames && hostnames.length > 0) {
          const ipv4Addresses = await dns.resolve4(hostnames[0]);
          dnsResult = {
            hostname: hostnames[0],
            ipv4Addresses
          };
        }
      } catch (e) {
        dnsResult = { error: e.message };
      }
    }
    
    res.json({
      detected: {
        ipv4: req.ipInfo.detected.ipv4,
        ipv6: req.ipInfo.detected.ipv6,
        source: req.ipInfo.detected.source
      },
      external_services: results.map(r => r.value || r.reason),
      dns_lookup: dnsResult,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Route 6: Alternative formats (XML, YAML, etc.)
app.get('/api/ip/:format', (req, res) => {
  const format = req.params.format.toLowerCase();
  const data = {
    ip: req.ipInfo.detected.ipv4 || req.ipInfo.detected.ipv6,
    timestamp: new Date().toISOString()
  };
  
  switch (format) {
    case 'xml':
      res.setHeader('Content-Type', 'application/xml');
      res.send(`<?xml version="1.0" encoding="UTF-8"?>
<response>
  <ip>${data.ip}</ip>
  <timestamp>${data.timestamp}</timestamp>
</response>`);
      break;
      
    case 'yaml':
      res.setHeader('Content-Type', 'application/yaml');
      res.send(`ip: ${data.ip}\ntimestamp: ${data.timestamp}`);
      break;
      
    case 'csv':
      res.setHeader('Content-Type', 'text/csv');
      res.send(`ip,timestamp\n${data.ip},${data.timestamp}`);
      break;
      
    default:
      res.json(data);
  }
});

// Route 7: Debug route for detailed header inspection
app.get('/debug/headers', (req, res) => {
  res.json({
    headers: req.headers,
    sensitive_headers_present: {
      authorization: !!req.headers.authorization,
      cookie: !!req.headers.cookie,
      'x-forwarded-for': !!req.headers['x-forwarded-for'],
      'x-real-ip': !!req.headers['x-real-ip']
    }
  });
});

// Start the server
app.listen(PORT, () => {
  console.log(`IP detection server running on port ${PORT}`);
  console.log(`Server time (UTC): ${new Date().toISOString()}`);
  console.log(`Access the server at: http://localhost:${PORT}`);
});