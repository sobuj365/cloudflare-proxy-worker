/**
 * Welcome to your secure, load-balancing SOCKS5 proxy worker (v2).
 * This version correctly handles both HTTPS (CONNECT) and HTTP (GET, POST, etc.) requests.
 * * It performs the following steps:
 * 1.  Authenticates incoming requests using a username and password.
 * 2.  Parses a list of your SOCKS5 proxies.
 * 3.  Selects one proxy at random for each request (load balancing).
 * 4.  Checks if the request is for HTTPS (CONNECT) or standard HTTP.
 * 5.  Handles the request accordingly by either tunneling or fetching.
 */

// A library to help create SOCKS5 connections within Cloudflare Workers.
// This is included directly to avoid external dependencies.
const socks5 = {};
socks5.connect = async function (proxy, targetHost, targetPort) {
  const socket = connect({ hostname: proxy.host, port: proxy.port });
  const writer = socket.writable.getWriter();
  const reader = socket.readable.getReader();
  const encoder = new TextEncoder();

  // SOCKS5 Greeting
  await writer.write(new Uint8Array([0x05, 0x01, 0x02])); // Version 5, 1 auth method, Username/Password
  let response = (await reader.read()).value;
  if (!response || response[0] !== 0x05 || response[1] !== 0x02) {
    socket.close();
    throw new Error('SOCKS5 authentication method negotiation failed.');
  }

  // SOCKS5 Username/Password Authentication
  const userBytes = encoder.encode(proxy.user);
  const passBytes = encoder.encode(proxy.pass);
  const authPacket = new Uint8Array([0x01, userBytes.length, ...userBytes, passBytes.length, ...passBytes]);
  await writer.write(authPacket);
  response = (await reader.read()).value;
  if (!response || response[0] !== 0x01 || response[1] !== 0x00) {
    socket.close();
    throw new Error('SOCKS5 proxy authentication failed.');
  }

  // SOCKS5 Connection Request
  const hostBytes = encoder.encode(targetHost);
  const portBytes = new Uint8Array([(targetPort >> 8) & 0xff, targetPort & 0xff]);
  const connectPacket = new Uint8Array([0x05, 0x01, 0x00, 0x03, hostBytes.length, ...hostBytes, ...portBytes]);
  await writer.write(connectPacket);
  response = (await reader.read()).value;
  if (!response || response[0] !== 0x05 || response[1] !== 0x00) {
    socket.close();
    throw new Error(`SOCKS5 connection failed. Error code: ${response ? response[1] : 'N/A'}`);
  }

  writer.releaseLock();
  reader.releaseLock();
  return socket;
};


export default {
  async fetch(request, env, ctx) {
    // --- Step 1: Authentication ---
    const authHeader = request.headers.get('Proxy-Authorization');
    if (!authHeader || !authHeader.startsWith('Basic ')) {
      return new Response('Proxy Authentication Required', {
        status: 407,
        headers: { 'Proxy-Authenticate': 'Basic realm="Secure Proxy Gateway"' },
      });
    }

    try {
      const decodedCreds = atob(authHeader.substring(6));
      const [user, pass] = decodedCreds.split(':');
      const users = JSON.parse(env.USERS_JSON);
      if (!users.some(entry => entry.user === user && entry.pass === pass)) {
        throw new Error("Invalid credentials");
      }
    } catch (err) {
      return new Response('Invalid Credentials', { status: 407 });
    }

    // --- Step 2: Choose a Proxy (Load Balancing) ---
    let chosenProxy;
    try {
      const proxies = JSON.parse(env.PROXIES_JSON);
      chosenProxy = proxies[Math.floor(Math.random() * proxies.length)];
    } catch (err) {
      return new Response('Proxy configuration error', { status: 500 });
    }

    // --- Step 3: Handle Request Based on Method ---

    // ** Handling for HTTPS traffic **
    if (request.method === 'CONNECT') {
      const url = new URL(request.url);
      try {
        const socket = await socks5.connect(chosenProxy, url.hostname, parseInt(url.port) || 443);
        const { readable, writable } = new TransformStream();
        socket.readable.pipeTo(writable).catch(() => {});
        request.body.pipeTo(socket.writable).catch(() => {});
        return new Response(readable, { status: 200, statusText: 'Connection established' });
      } catch (err) {
        return new Response(err.message, { status: 502 });
      }
    } 
    
    // ** Handling for HTTP traffic (GET, POST, etc.) **
    else {
      // For standard HTTP requests, we create a custom `fetch` that uses our SOCKS5 proxy.
      // The `connect` API in Cloudflare Workers allows us to define a custom TCP socket for a fetch request.
      try {
        const socksSocket = await socks5.connect(chosenProxy, new URL(request.url).hostname, parseInt(new URL(request.url).port) || 80);
        
        // Make the final fetch request using the established SOCKS socket
        return fetch(request, {
          duplex: 'half',
          // The 'connect' property is a special Cloudflare feature that lets us use our own socket.
          connect: {
            async connect(options) {
              return socksSocket;
            }
          }
        });

      } catch (err) {
        return new Response(err.message, { status: 502 });
      }
    }
  },
};

