export default {
  async fetch(request, env) {
    try {
      return await handleRequest(request, env);
    } catch (err) {
      console.error("Worker error:", err);
      return new Response("Internal Worker Error", { status: 500 });
    }
  },
};

async function handleRequest(request, env) {
  const url = new URL(request.url);

  // ===== 固定代理出口 =====
  const proxyIP = "ProxyIP.Oracle.cmliussss.net";

  // ===== 密码处理 =====
  const password = env.PASSWORD || "myStrongPassword";
  const sha224Password = await sha224(password);
  const sha256Password = await sha256(password);

  // ===== 订阅接口 =====
  if (url.pathname === "/" + password) {
    let node = `trojan://${password}@${url.host}:443?peer=${proxyIP}#Trojan-Worker`;
    return new Response(node, { status: 200, headers: { "Content-Type": "text/plain" } });
  }

  // ===== WebSocket 处理 =====
  if (request.headers.get("Upgrade") === "websocket") {
    return await trojanOverWSHandler(request, { sha224Password, sha256Password, proxyIP });
  }

  return new Response("Hello Worker!", { status: 200 });
}

/**
 * Trojan over WebSocket Handler
 */
async function trojanOverWSHandler(request, { sha224Password, sha256Password, proxyIP }) {
  const [client, server] = Object.values(new WebSocketPair());
  server.accept();

  server.addEventListener("message", async (event) => {
    try {
      let data = event.data;
      if (typeof data === "string") {
        server.send("pong");
        return;
      }

      let parsed = parseTrojanHeader(new Uint8Array(await data.arrayBuffer()), sha224Password, sha256Password);
      if (parsed.hasError) {
        console.log("认证失败:", parsed.message);
        server.close();
        return;
      }

      console.log("认证成功, 目标:", parsed.address, parsed.port);

      // === 强制走 ProxyIP 出口 ===
      let connected = await connectProxy(proxyIP, parsed.address, parsed.port);

      if (!connected) {
        server.send("无法连接代理服务器");
        server.close();
        return;
      }

      server.send(`流量已落地到 ${proxyIP}, 转发目标 ${parsed.address}:${parsed.port}`);
    } catch (err) {
      console.error("WS error:", err);
      server.close();
    }
  });

  return new Response(null, { status: 101, webSocket: client });
}

/**
 * 模拟连接代理服务器
 * 实际上这里应该改成 TCP/UDP 转发逻辑
 */
async function connectProxy(proxyIP, targetHost, targetPort) {
  try {
    console.log(`连接代理: ${proxyIP} -> ${targetHost}:${targetPort}`);
    // TODO: 在这里实现真正的 TCP 转发逻辑
    return true;
  } catch (e) {
    console.error("代理连接失败:", e);
    return false;
  }
}

/**
 * 解析 Trojan 协议 Header
 */
function parseTrojanHeader(buffer, sha224Password, sha256Password) {
  if (buffer.byteLength < 56) {
    return { hasError: true, message: "invalid length" };
  }

  let passwordHex = [...buffer.slice(0, 64)]
    .map((x) => String.fromCharCode(x))
    .join("")
    .trim();

  if (passwordHex !== sha224Password && passwordHex !== sha256Password) {
    return { hasError: true, message: "invalid password" };
  }

  // TODO: 从 buffer 中解析目标地址和端口
  return {
    hasError: false,
    address: "example.com",
    port: 443,
  };
}

/**
 * SHA224
 */
async function sha224(message) {
  const msgBuffer = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest("SHA-224", msgBuffer);
  return bufferToHex(hashBuffer);
}

/**
 * SHA256
 */
async function sha256(message) {
  const msgBuffer = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest("SHA-256", msgBuffer);
  return bufferToHex(hashBuffer);
}

/**
 * ArrayBuffer → Hex
 */
function bufferToHex(buffer) {
  return [...new Uint8Array(buffer)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
