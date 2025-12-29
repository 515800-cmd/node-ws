
const os = require('os');
const http = require('http');
const fs = require('fs');
const axios = require('axios');
const net = require('net');
const path = require('path');
const crypto = require('crypto');
const { Buffer } = require('buffer');
const { exec, execSync } = require('child_process');
const { WebSocket, createWebSocketStream } = require('ws');

const UUID = process.env.UUID || 'd9a36967-7314-4397-9baf-ff5cfd894e0f';
const NEZHA_SERVER = process.env.NEZHA_SERVER || '';
const NEZHA_PORT = process.env.NEZHA_PORT || '';
const NEZHA_KEY = process.env.NEZHA_KEY || '';
const DOMAIN = process.env.DOMAIN || '1234.abc.com';
const AUTO_ACCESS = process.env.AUTO_ACCESS || false;
const WSPATH = process.env.WSPATH || UUID.slice(0, 8);
const SUB_PATH = process.env.SUB_PATH || '515800';
const NAME = process.env.NAME || '';
const PORT = process.env.PORT || 3000;

let ISP = '';
const GetISP = async () => {
  try {
    const res = await axios.get('https://api.ip.sb/geoip');
    const data = res.data;
    ISP = `${data.country_code}-${data.isp}`.replace(/ /g, '_');
  } catch (e) {
    ISP = 'Unknown';
  }
}
GetISP();

const httpServer = http.createServer((req, res) => {
  if (req.url === '/') {
    const filePath = path.join(__dirname, 'index.html');
    fs.readFile(filePath, 'utf8', (err, content) => {
      if (err) {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end('Hello world!');
        return;
      }
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(content);
    });
    return;
  } else if (req.url === `/${SUB_PATH}`) {
    const namePart = NAME ? `${NAME}-${ISP}` : ISP;
    const vlessURL = `vless://${UUID}@cdns.doon.eu.org:443?encryption=none&security=tls&sni=${DOMAIN}&fp=chrome&type=ws&host=${DOMAIN}&path=%2F${WSPATH}#${namePart}`;
    const trojanURL = `trojan://${UUID}@cdns.doon.eu.org:443?security=tls&sni=${DOMAIN}&fp=chrome&type=ws&host=${DOMAIN}&path=%2F${WSPATH}#${namePart}`;
    const subscription = vlessURL + '\n' + trojanURL;
    const base64Content = Buffer.from(subscription).toString('base64');
    
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end(base64Content + '\n');
  } else {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not Found\n');
  }
});

const wss = new WebSocket.Server({ server: httpServer });
const uuid = UUID.replace(/-/g, "");
const DNS_SERVERS = ['8.8.4.4', '1.1.1.1'];

function resolveHost(host) {
  return new Promise((resolve, reject) => {
    if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(host)) {
      resolve(host);
      return;
    }
    let attempts = 0;
    function tryNextDNS() {
      if (attempts >= DNS_SERVERS.length) {
        reject(new Error(`Failed to resolve ${host} with all DNS servers`));
        return;
      }
      const dnsServer = DNS_SERVERS[attempts];
      attempts++;
      const dnsQuery = `https://dns.google/resolve?name=${encodeURIComponent(host)}&type=A`;
      axios.get(dnsQuery, {
        timeout: 5000,
        headers: {
          'Accept': 'application/dns-json'
        }
      })
      .then(response => {
        const data = response.data;
        if (data.Status === 0 && data.Answer && data.Answer.length > 0) {
          const ip = data.Answer.find(record => record.type === 1);
          if (ip) {
            resolve(ip.data);
            return;
          }
        }
        tryNextDNS();
      })
      .catch(error => {
        tryNextDNS();
      });
    }
    
    tryNextDNS();
  });
}

function handleVlessConnection(ws, msgBuffer) {
  try {
    // 检查Buffer长度避免越界
    if (msgBuffer.length < 2) {
      console.error('Invalid buffer length');
      ws.close();
      return false;
    }

    const VERSION = msgBuffer.readUInt8(0);
    if (VERSION !== 0) {
      console.error('Unsupported version');
      ws.close();
      return false;
    }

    // 检查UUID长度
    if (msgBuffer.length < 17) {
      console.error('Buffer too short for UUID');
      ws.close();
      return false;
    }

    const id = msgBuffer.slice(1, 17);
    const expectedUUID = uuid.match(/.{1,2}/g).map(byte => parseInt(byte, 16));
    if (!expectedUUID.every((v, i) => v === id[i])) {
      console.error('UUID mismatch');
      ws.close();
      return false;
    }

    // 检查CMD长度
    if (msgBuffer.length < 18) {
      console.error('Buffer too short for CMD');
      ws.close();
      return false;
    }

    let offset = 17;
    const cmdLen = msgBuffer.readUInt8(offset);
    offset += 1 + cmdLen; // 跳过CMD内容

    // 检查端口字段
    if (msgBuffer.length < offset + 2) {
      console.error('Buffer too short for port');
      ws.close();
      return false;
    }

    const port = msgBuffer.readUInt16BE(offset);
    offset += 2;

    // 检查地址类型字段
    if (msgBuffer.length < offset + 1) {
      console.error('Buffer too short for address type');
      ws.close();
      return false;
    }

    const ATYP = msgBuffer.readUInt8(offset);
    offset += 1;

    let host = '';
    if (ATYP === 1) { // IPv4
      if (msgBuffer.length < offset + 4) {
        console.error('Buffer too short for IPv4');
        ws.close();
        return false;
      }
      host = Array.from(msgBuffer.slice(offset, offset + 4)).join('.');
      offset += 4;
    } else if (ATYP === 2) { // Domain
      if (msgBuffer.length < offset + 1) {
        console.error('Buffer too short for domain length');
        ws.close();
        return false;
      }
      const domainLen = msgBuffer.readUInt8(offset);
      offset += 1;
      if (msgBuffer.length < offset + domainLen) {
        console.error('Buffer too short for domain');
        ws.close();
        return false;
      }
      host = new TextDecoder().decode(msgBuffer.slice(offset, offset + domainLen));
      offset += domainLen;
    } else if (ATYP === 3) { // IPv6
      if (msgBuffer.length < offset + 16) {
        console.error('Buffer too short for IPv6');
        ws.close();
        return false;
      }
      host = Array.from({ length: 8 }, (_, i) => 
        msgBuffer.readUInt16BE(offset + i * 2).toString(16)
      ).join(':');
      offset += 16;
    } else {
      console.error('Unsupported address type');
      ws.close();
      return false;
    }

    // 发送响应
    ws.send(new Uint8Array([VERSION, 0]));

    // 建立连接
    const duplex = createWebSocketStream(ws);
    resolveHost(host)
      .then(resolvedIP => {
        const remoteSocket = net.connect({ host: resolvedIP, port }, function() {
          remoteSocket.on('close', () => ws.close());
          remoteSocket.on('error', () => ws.close());
          duplex.on('error', () => remoteSocket.destroy());
          duplex.on('close', () => remoteSocket.destroy());
          duplex.pipe(remoteSocket);
          remoteSocket.pipe(duplex);
        });
      })
      .catch(error => {
        console.error('DNS resolution failed:', error.message);
        ws.close();
      });

    return true;
  } catch (error) {
    console.error('Error in handleVlessConnection:', error);
    ws.close();
    return false;
  }
}

wss.on('connection', (ws, req) => {
  if (req.url.startsWith(`/${WSPATH}`)) {
    ws.on('message', msg => {
      try {
        const buffer = Buffer.isBuffer(msg) ? msg : Buffer.from(msg);
        handleVlessConnection(ws, buffer);
      } catch (error) {
        console.error('WebSocket message error:', error);
        ws.close();
      }
    });
    
    ws.on('error', error => {
      console.error('WebSocket error:', error);
    });
    
    ws.on('close', () => {
      console.log('WebSocket connection closed');
    });
  } else {
    ws.close();
  }
});

httpServer.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
  
  if (NEZHA_SERVER && NEZHA_KEY) {
    const command = `nohup ./nezha-agent -s ${NEZHA_SERVER}:${NEZHA_PORT} -p ${NEZHA_KEY} --tls > nezha.log 2>&1 &`;
    exec(command, (error, stdout, stderr) => {
      if (error) {
        console.error(`Nezha agent error: ${error}`);
        return;
      }
      console.log('Nezha agent started successfully');
    });
  } else {
    console.log('NEZHA variable is empty, skip running');
  }
  
  if (AUTO_ACCESS) {
    const autoAccess = () => {
      axios.get(`http://localhost:${PORT}`)
        .then(() => console.log('Automatic Access Task added successfully'))
        .catch(error => console.error('Automatic access failed:', error.message));
    };
    setInterval(autoAccess, 60000);
    autoAccess();
  }
});
