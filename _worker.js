import { connect } from "cloudflare:sockets";

let password = '';
// 强制落地 IP（默认）——如果希望由环境变量覆盖，可设置 env.PROXYIP
let proxyIP = 'ProxyIP.Oracle.cmliussss.net';
let DNS64Server = '';
//let sub = '';
let subConverter = atob('U1VCQVBfQ09OVkVSVEVS'); 

export default {
  async fetch(request, env, ctx) {
    try {
      if (typeof env.PROXYIP == 'string') proxyIP = env.PROXYIP;
      if (typeof env.UUID == 'string') password = env.UUID.toLowerCase();
      if (typeof env.DNS64 == 'string') DNS64Server = env.DNS64;
      if (typeof env.SUBCONVERTER == 'string') subConverter = env.SUBCONVERTER;

      const upgradeHeader = request.headers.get('Upgrade');
      if (!upgradeHeader || upgradeHeader !== 'websocket') {
        return new Response(JSON.stringify(request.cf), { status: 200 });
      }
      const [client, webSocket] = Object.values(new WebSocketPair());
      webSocket.accept();
      let address = '';
      let portWithRandomLog = 443;
      handleUDPOutBound(webSocket);
      return new Response(null, { status: 101, webSocket: client });
    } catch (err) {
      return new Response('Error: ' + err.message, { status: 500 });
    }
  }
};

function handleUDPOutBound(webSocket) {
  webSocket.addEventListener('message', async (event) => {
    const data = event.data;
    let addressRemote = '';
    let portRemote = 0;
    let log = (...args) => console.log(...args);

    try {
      if (data instanceof ArrayBuffer) {
        const buffer = new Uint8Array(data);
        const version = buffer[0];
        if (version === 5) {
          // Socks5
          const cmd = buffer[1];
          if (cmd === 1) {
            const atyp = buffer[3];
            let offset = 4;
            if (atyp === 1) {
              addressRemote = buffer.slice(offset, offset + 4).join('.');
              offset += 4;
            } else if (atyp === 3) {
              const len = buffer[offset];
              offset += 1;
              addressRemote = new TextDecoder().decode(buffer.slice(offset, offset + len));
              offset += len;
            } else if (atyp === 4) {
              addressRemote = buffer.slice(offset, offset + 16);
              offset += 16;
            }
            portRemote = (buffer[offset] << 8) | buffer[offset + 1];
            offset += 2;
          }
        }
      }
      if (addressRemote) {
        handleTCPOutBound(webSocket, addressRemote, portRemote, log);
      }
    } catch (e) {
      console.error('UDP outbound error', e);
      webSocket.close();
    }
  });
}

async function handleTCPOutBound(webSocket, addressRemote, portRemote, log) {
  let enableSocks = false;
  let enableHttp = false;
  let tcpSocket;

  // === START: 强制所有出站走 proxyIP ===
  try {
    if (proxyIP && proxyIP.trim() !== '') {
      let forced = proxyIP.trim();
      let forcedHost = forced;
      let forcedPort = portRemote;
      if (forced.startsWith('[') && forced.includes(']:')) {
        const idx = forced.lastIndexOf(']:');
        forcedHost = forced.slice(0, idx + 1);
        forcedPort = Number(forced.slice(idx + 2)) || forcedPort;
      } else if (forced.includes(':') && !forced.includes('http')) {
        const parts = forced.split(':');
        if (parts.length === 2) {
          forcedHost = parts[0];
          forcedPort = Number(parts[1]) || forcedPort;
        }
      }
      addressRemote = forcedHost.toLowerCase();
      portRemote = Number(forcedPort) || portRemote;
      log(`强制落地代理: ${addressRemote}:${portRemote}`);
    }
  } catch (e) {
    console.error('强制落地 proxyIP 解析错误:', e);
  }
  // === END: 强制所有出站走 proxyIP ===

  async function retry() {
    if (enableSocks) {
      tcpSocket = await connectAndWrite(addressRemote, portRemote, true, enableHttp);
    } else {
      let p = proxyIP && proxyIP.trim() !== '' ? proxyIP.trim() : 'ProxyIP.Oracle.cmliussss.net';
      let pHost = p;
      let pPort = portRemote;
      if (p.startsWith('[') && p.includes(']:')) {
        const idx = p.lastIndexOf(']:');
        pHost = p.slice(0, idx + 1);
        pPort = Number(p.slice(idx + 2)) || pPort;
      } else if (p.includes(':') && !p.startsWith('http')) {
        const parts = p.split(':');
        if (parts.length === 2) {
          pHost = parts[0];
          pPort = Number(parts[1]) || pPort;
        }
      }
      tcpSocket = await connectAndWrite(pHost.toLowerCase() || addressRemote, pPort);
    }
    remoteSocketToWS(tcpSocket, webSocket, "ResponseHeader", false, log);
  }

  tcpSocket = await connectAndWrite(addressRemote, portRemote);
  remoteSocketToWS(tcpSocket, webSocket, "ResponseHeader", false, log);
}

async function connectAndWrite(host, port, useSocks = false, useHttp = false) {
  return await connect({ hostname: host, port: port });
}

function remoteSocketToWS(tcpSocket, webSocket, responseHeader, nat64, log) {
  (async () => {
    try {
      for await (const chunk of tcpSocket.readable) {
        webSocket.send(chunk);
      }
    } catch (err) {
      log('remoteSocketToWS error', err);
    }
  })();
}
