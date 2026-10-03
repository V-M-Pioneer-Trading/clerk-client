/**
 * @file A real HTTP stub standing in for auth-service.
 *
 * Real, not a mocked `fetch`: the fixture asserts what the client SENDS — the
 * method, the content type, the form body and the secret header — and a mock
 * would only prove the client called a function. The timeout case needs a
 * server that genuinely answers late, and the unreachable case needs a port
 * with genuinely nothing on it.
 */

import { createServer, type IncomingMessage, type Server } from "node:http";
import { once } from "node:events";
import type { AddressInfo } from "node:net";

/** The `center` object of a fixture case. Unknown keys fail the case. */
export interface CenterSpec {
  readonly notCalled?: true;
  readonly status?: number;
  readonly body?: string;
  readonly delayMs?: number;
  readonly transport?: "no-response";
}

const KNOWN_CENTER_KEYS = new Set([
  "notCalled",
  "status",
  "body",
  "delayMs",
  "transport",
]);

export const assertKnownCenterKeys = (caseName: string, center: object): void => {
  for (const key of Object.keys(center)) {
    if (!KNOWN_CENTER_KEYS.has(key)) {
      throw new Error(
        `${caseName}: unknown center key "${key}" — the vendored fixture describes a condition this stub cannot produce`
      );
    }
  }
};

/** Everything the client sent, as the wire saw it. */
export interface RecordedRequest {
  readonly method: string;
  readonly url: string;
  readonly contentType: string | undefined;
  readonly secretHeader: string | undefined;
  readonly accept: string | undefined;
  readonly body: string;
}

export interface StubCenter {
  /** The full endpoint URL, exactly as `AUTH_INTROSPECTION_URL` would hold it. */
  readonly url: string;
  /** Requests this stub actually received, in order. */
  readonly requests: RecordedRequest[];
  close(): Promise<void>;
}

const ENDPOINT_PATH = "/auth/v1/introspect";

const readBody = async (req: IncomingMessage): Promise<string> => {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString("utf8");
};

/** A port with nothing listening on it: bind one, then give it back. */
const closedPort = async (): Promise<number> => {
  const probe = createServer();
  probe.listen(0, "127.0.0.1");
  await once(probe, "listening");
  const { port } = probe.address() as AddressInfo;
  probe.close();
  await once(probe, "close");
  return port;
};

export async function startStubCenter(spec: CenterSpec): Promise<StubCenter> {
  if (spec.transport === "no-response") {
    // Connection refused. The client's own call count is asserted from the
    // fetch spy, since there is no server here to count for us.
    const port = await closedPort();
    return {
      url: `http://127.0.0.1:${String(port)}${ENDPOINT_PATH}`,
      requests: [],
      close: () => Promise.resolve(),
    };
  }

  const requests: RecordedRequest[] = [];
  const pending = new Set<NodeJS.Timeout>();

  const server: Server = createServer((req, res) => {
    void (async () => {
      requests.push({
        method: req.method ?? "",
        url: req.url ?? "",
        contentType: req.headers["content-type"],
        secretHeader: req.headers["x-introspection-secret"] as string | undefined,
        accept: req.headers.accept,
        body: await readBody(req),
      });

      const send = () => {
        if (res.writableEnded) return;
        res.writeHead(spec.status ?? 200, { "Content-Type": "application/json" });
        res.end(spec.body ?? "");
      };

      if (spec.delayMs !== undefined && spec.delayMs > 0) {
        const timer = setTimeout(() => {
          pending.delete(timer);
          send();
        }, spec.delayMs);
        pending.add(timer);
        return;
      }
      send();
    })();
  });

  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const { port } = server.address() as AddressInfo;

  return {
    url: `http://127.0.0.1:${String(port)}${ENDPOINT_PATH}`,
    requests,
    close: async () => {
      // A delayed answer nobody is waiting for would otherwise hold the suite
      // open for its full delay.
      for (const timer of pending) clearTimeout(timer);
      pending.clear();
      server.closeAllConnections();
      server.close();
      await once(server, "close");
    },
  };
}

/**
 * A stub that answers instantly with a body far larger than the client's cap,
 * used to prove the response read is bounded.
 */
export async function startOversizedCenter(bytes: number): Promise<StubCenter> {
  const requests: RecordedRequest[] = [];
  const server = createServer((req, res) => {
    void (async () => {
      requests.push({
        method: req.method ?? "",
        url: req.url ?? "",
        contentType: req.headers["content-type"],
        secretHeader: req.headers["x-introspection-secret"] as string | undefined,
        accept: req.headers.accept,
        body: await readBody(req),
      });
      res.writeHead(200, { "Content-Type": "application/json" });
      // Valid JSON if it were ever read to the end — so a client that failed
      // this test by reading it all would otherwise have answered 200.
      res.write('{"active":true,"sub":"user_x","scope":"' + "a".repeat(bytes));
      res.end('","exp":4102444800,"kind":"operator"}');
    })();
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${String(port)}${ENDPOINT_PATH}`,
    requests,
    close: async () => {
      server.closeAllConnections();
      server.close();
      await once(server, "close");
    },
  };
}

/**
 * A stub that answers 302 to a second stub. Proves the client does not follow
 * it: the caller secret must never travel to a host the center named.
 */
export async function startRedirectingCenter(): Promise<
  StubCenter & { readonly destination: StubCenter }
> {
  const destination = await startStubCenter({
    status: 200,
    body: '{"active":true,"sub":"user_redirected","scope":"fleet:control","exp":4102444800,"kind":"operator"}',
  });

  const requests: RecordedRequest[] = [];
  const server = createServer((req, res) => {
    void (async () => {
      requests.push({
        method: req.method ?? "",
        url: req.url ?? "",
        contentType: req.headers["content-type"],
        secretHeader: req.headers["x-introspection-secret"] as string | undefined,
        accept: req.headers.accept,
        body: await readBody(req),
      });
      res.writeHead(302, { Location: destination.url });
      res.end();
    })();
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const { port } = server.address() as AddressInfo;

  return {
    url: `http://127.0.0.1:${String(port)}${ENDPOINT_PATH}`,
    requests,
    destination,
    close: async () => {
      server.closeAllConnections();
      server.close();
      await once(server, "close");
      await destination.close();
    },
  };
}
