/**
 * Welcome to your secure, load-balancing SOCKS5 proxy worker.
 * * This worker performs the following steps:
 * 1.  Authenticates incoming requests using a username and password.
 * 2.  Parses a list of your SOCKS5 proxies.
 * 3.  Selects one proxy at random for each request (load balancing).
 * 4.  Connects to the destination website through the chosen SOCKS5 proxy.
 * 5.  Streams the data back and forth between the client and the destination.
 */

export default {
  async fetch(request, env, ctx) {

    // --- Step 1: Authenticate the incoming request ---
    const authHeader = request.headers.get('Proxy-Authorization');
    if (!authHeader || !authHeader.startsWith('Basic ')) {
      return new Response('Proxy Authentication Required', {
        status: 407,
        headers: { 'Proxy-Authenticate': 'Basic realm="Secure Proxy Gateway"' },
      });
    }

    const encodedCreds = authHeader.substring(6);
    try {
      const decodedCreds = atob(encodedCreds);
      const [user, pass] = decodedCreds.split(':');

      // Parse the allowed user list from the secret
      const users = JSON.parse(env.USERS_JSON);
      const isAuthenticated = users.some(
        (entry) => entry.user === user && entry.pass === pass
      );

      if (!isAuthenticated) {
        throw new Error("Invalid credentials");
      }
    } catch (err) {
      console.error("Authentication error:", err.message);
      return new Response('Invalid Credentials', { status: 407 });
    }

    // --- Step 2: Choose a SOCKS5 proxy (Load Balancing) ---
    let chosenProxy;
    try {
      const proxies = JSON.parse(env.PROXIES_JSON);
      if (!proxies || proxies.length === 0) {
        throw new Error("PROXIES_JSON secret is empty or invalid.");
      }
      // Randomly select a proxy for each request. This is the load balancing.
      chosenProxy = proxies[Math.floor(Math.random() * proxies.length)];
    } catch (err) {
      console.error("Proxy selection error:", err.message);
      return new Response('Proxy configuration error', { status: 500 });
    }
    
    // --- Step 3: Connect to the destination through the proxy ---
    try {
      // The CONNECT method is used for HTTPS connections.
      // We extract the destination hostname and port from the URL path.
      const url = new URL(request.url);
      const targetHost = url.hostname;
      const targetPort = parseInt(url.port) || 443;

      // Establish a TCP socket to the destination through the SOCKS5 proxy.
      const socket = await socks5Connect(chosenProxy, targetHost, targetPort);

      // Once connected, we can stream data.
      // We create a pair of streams to pipe the data between the client and the target.
      const { readable, writable } = new TransformStream();

      // Pipe the data from the established socket to the client.
      socket.readable.pipeTo(writable).catch(err => {
        console.error(`Socket pipeTo error: ${err}`);
      });

      // Pipe the data from the client to the established socket.
      request.body.pipeTo(socket.writable).catch(err => {
        console.error(`Request body pipeTo error: ${err}`);
      });

      // Return a response that allows bi-directional streaming.
      // For a CONNECT request, the response body should be the readable stream.
      return new Response(readable, { status: 200, statusText: 'Connection established' });
      
    } catch (err) {
      console.error(`Error during proxy connection: ${err}`);
      return new Response(err.message, { status: 502 }); // 502 Bad Gateway
    }
  },
};

/**
 * Establishes a TCP connection to a target host and port through a SOCKS5 proxy.
 * This function handles the SOCKS5 handshake protocol.
 * @param {object} proxy - The proxy object with host, port, user, and pass.
 * @param {string} targetHost - The destination hostname.
 * @param {number} targetPort - The destination port.
 * @returns {Promise<Socket>} - A promise that resolves with the established TCP socket.
 */
async function socks5Connect(proxy, targetHost, targetPort) {
  // `connect` is a Cloudflare Workers API to open a raw TCP socket.
  const socket = connect({
    hostname: proxy.host,
    port: proxy.port,
  });

  const writer = socket.writable.getWriter();
  const reader = socket.readable.getReader();
  const encoder = new TextEncoder();

  // SOCKS5 Handshake - Step 1: Greeting and Authentication Method Selection
  // We send a greeting that says we support "Username/Password" authentication (method 0x02).
  await writer.write(new Uint8Array([
    0x05, // SOCKS version 5
    0x01, // Number of authentication methods supported
    0x02  // Authentication method: Username/Password
  ]));

  let response = (await reader.read()).value;
  if (!response || response[0] !== 0x05 || response[1] !== 0x02) {
    socket.close();
    throw new Error('SOCKS5 authentication method negotiation failed.');
  }

  // SOCKS5 Handshake - Step 2: Username/Password Authentication
  const userBytes = encoder.encode(proxy.user);
  const passBytes = encoder.encode(proxy.pass);
  const authPacket = new Uint8Array([
    0x01, // Auth version
    userBytes.length,
    ...userBytes,
    passBytes.length,
    ...passBytes,
  ]);
  await writer.write(authPacket);

  response = (await reader.read()).value;
  // A successful auth response is [0x01, 0x00]
  if (!response || response[0] !== 0x01 || response[1] !== 0x00) {
    socket.close();
    throw new Error('SOCKS5 proxy authentication failed. Check proxy username/password.');
  }

  // SOCKS5 Handshake - Step 3: Connection Request
  const hostBytes = encoder.encode(targetHost);
  const portBytes = new Uint8Array([(targetPort >> 8) & 0xff, targetPort & 0xff]);
  const connectPacket = new Uint8Array([
    0x05, // SOCKS version
    0x01, // Command: CONNECT
    0x00, // Reserved, must be 0x00
    0x03, // Address type: Domain name
    hostBytes.length,
    ...hostBytes,
    ...portBytes,
  ]);
  await writer.write(connectPacket);

  response = (await reader.read()).value;
  // A successful connection response has 0x00 in the second byte.
  if (!response || response[0] !== 0x05 || response[1] !== 0x00) {
    socket.close();
    throw new Error(`SOCKS5 connection to target failed. Proxy server replied with error code: ${response ? response[1] : 'N/A'}`);
  }

  // The SOCKS5 handshake is complete! The socket is now connected to the target.
  // We release the writer and reader so the streams can be piped directly.
  writer.releaseLock();
  reader.releaseLock();

  return socket;
}
