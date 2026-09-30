/**
 * @file The caller side of the center's machine-token endpoint.
 *
 * `fetch` and the clock are injected, so each test states exactly what the
 * center said and what time it is.
 */

import { createCentralM2MTokenSource } from "../src";

const URL_ = "http://localhost:3005/auth/v1/m2m-token";
const SECRET = "caller-secret-do-not-leak";
const T0 = 1_000_000; // seconds; the token's iat
const LIFETIME = 86_400;

const jwt = (iat: number, exp: number, tag: string): string => {
  const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
  return `${b64({ alg: "RS256" })}.${b64({ sub: "mch_x", iat, exp, tag })}.sig-${tag}`;
};
const TOKEN_A = jwt(T0, T0 + LIFETIME, "A");
const NO_LIFETIME = `e30.${Buffer.from(JSON.stringify({ sub: "mch_x" })).toString("base64url")}.sig-nolife`;
const TOKEN_B = jwt(T0 + LIFETIME / 2, T0 + LIFETIME * 1.5, "B");

const ok = (token: string): Response =>
  new Response(JSON.stringify({ token, expires_at: 0 }), { status: 200 });
const status = (code: number): Response => new Response(JSON.stringify({ error: "x" }), { status: code });
const timeout = (): Error =>
  Object.assign(new Error("The operation was aborted due to timeout"), { name: "TimeoutError" });

type Step = Response | Error;
const script = (...steps: Step[]) => {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const fetchMock = (async (url: string, init: RequestInit) => {
    calls.push({ url, init });
    const step = steps.shift();
    if (step === undefined) throw new Error("unscripted call");
    if (step instanceof Error) throw step;
    return step;
  }) as unknown as typeof fetch;
  return { calls, fetchMock };
};

const clock = (seconds: number) => {
  const c = { seconds };
  return { c, now: () => c.seconds * 1000 };
};

describe("createCentralM2MTokenSource", () => {
  it("POSTs with the secret header, an empty body and a timeout signal, and returns the token", async () => {
    const { calls, fetchMock } = script(ok(TOKEN_A));
    const { now } = clock(T0);
    const source = createCentralM2MTokenSource({ url: URL_, secret: SECRET, fetch: fetchMock, now });

    await expect(source.getToken()).resolves.toBe(TOKEN_A);

    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe(URL_);
    expect(calls[0]!.init.method).toBe("POST");
    expect(calls[0]!.init.headers).toEqual({ "X-Service-Secret": SECRET });
    expect(calls[0]!.init.body).toBeUndefined();
    expect(calls[0]!.init.signal).toBeInstanceOf(AbortSignal);
  });

  it("serves the cache before half the lifetime and refreshes after it", async () => {
    const { calls, fetchMock } = script(ok(TOKEN_A), ok(TOKEN_B));
    const { c, now } = clock(T0);
    const source = createCentralM2MTokenSource({ url: URL_, secret: SECRET, fetch: fetchMock, now });

    await source.getToken();
    c.seconds = T0 + LIFETIME / 2 - 1;
    await expect(source.getToken()).resolves.toBe(TOKEN_A);
    expect(calls).toHaveLength(1);

    c.seconds = T0 + LIFETIME / 2;
    await expect(source.getToken()).resolves.toBe(TOKEN_B);
    expect(calls).toHaveLength(2);
    // and the new token is now the cached one
    await expect(source.getToken()).resolves.toBe(TOKEN_B);
    expect(calls).toHaveLength(2);
  });

  it("makes one request for concurrent callers", async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    let count = 0;
    const fetchMock = (async () => {
      count += 1;
      await gate;
      return ok(TOKEN_A);
    }) as unknown as typeof fetch;
    const { now } = clock(T0);
    const source = createCentralM2MTokenSource({ url: URL_, secret: SECRET, fetch: fetchMock, now });

    const all = Promise.all([source.getToken(), source.getToken(), source.getToken()]);
    release();
    await expect(all).resolves.toEqual([TOKEN_A, TOKEN_A, TOKEN_A]);
    expect(count).toBe(1);
  });

  it("returns the cached token when a refresh fails and it has not expired", async () => {
    const { fetchMock } = script(ok(TOKEN_A), status(503), status(503));
    const { c, now } = clock(T0);
    const source = createCentralM2MTokenSource({ url: URL_, secret: SECRET, fetch: fetchMock, now });

    await source.getToken();
    c.seconds = T0 + LIFETIME / 2 + 10;
    await expect(source.getToken()).resolves.toBe(TOKEN_A);
  });

  it("fails once the cached token has expired and the refresh fails", async () => {
    const { fetchMock } = script(ok(TOKEN_A), status(503), status(503));
    const { c, now } = clock(T0);
    const source = createCentralM2MTokenSource({ url: URL_, secret: SECRET, fetch: fetchMock, now });

    await source.getToken();
    c.seconds = T0 + LIFETIME;
    await expect(source.getToken()).rejects.toThrow(/503/);
  });

  it("retries once, immediately, after a 503", async () => {
    const { calls, fetchMock } = script(status(503), ok(TOKEN_A));
    const { now } = clock(T0);
    const source = createCentralM2MTokenSource({ url: URL_, secret: SECRET, fetch: fetchMock, now });

    await expect(source.getToken()).resolves.toBe(TOKEN_A);
    expect(calls).toHaveLength(2);
  });

  it("retries once after a timeout", async () => {
    const { calls, fetchMock } = script(timeout(), ok(TOKEN_A));
    const { now } = clock(T0);
    const source = createCentralM2MTokenSource({ url: URL_, secret: SECRET, fetch: fetchMock, now });

    await expect(source.getToken()).resolves.toBe(TOKEN_A);
    expect(calls).toHaveLength(2);
  });

  it("retries only once: two 503s fail with exactly two requests", async () => {
    const { calls, fetchMock } = script(status(503), status(503), ok(TOKEN_A));
    const { now } = clock(T0);
    const source = createCentralM2MTokenSource({ url: URL_, secret: SECRET, fetch: fetchMock, now });

    await expect(source.getToken()).rejects.toThrow();
    expect(calls).toHaveLength(2);
  });

  it("does not retry a 401, and says the center did not recognise the caller", async () => {
    const { calls, fetchMock } = script(status(401), ok(TOKEN_A));
    const { now } = clock(T0);
    const source = createCentralM2MTokenSource({ url: URL_, secret: SECRET, fetch: fetchMock, now });

    await expect(source.getToken()).rejects.toThrow(/did not recognise this caller/);
    expect(calls).toHaveLength(1);
  });

  describe("secrecy", () => {
    const failures: Array<[string, Step[]]> = [
      ["a 401", [status(401)]],
      ["two 503s", [status(503), status(503)]],
      ["two timeouts", [timeout(), timeout()]],
      ["a network error", [new Error(`connect ECONNREFUSED ${SECRET} ${TOKEN_A}`)]],
      ["an unexpected status", [status(500)]],
      ["a body with no token", [new Response("{}", { status: 200 })]],
      ["a token with no lifetime", [ok(NO_LIFETIME)]],
      ["a non-JSON body", [new Response(`${SECRET} ${TOKEN_A}`, { status: 200 })]],
    ];

    it.each(failures)("an error for %s carries neither the secret nor a token", async (_name, steps) => {
      const { fetchMock } = script(...steps);
      const { now } = clock(T0);
      const source = createCentralM2MTokenSource({ url: URL_, secret: SECRET, fetch: fetchMock, now });

      const err = await source.getToken().then(
        () => null,
        (e: unknown) => e as Error
      );
      expect(err).toBeInstanceOf(Error);
      const text = `${err!.message}\n${err!.stack ?? ""}\n${String((err as { cause?: unknown }).cause ?? "")}`;
      expect(text).not.toContain(SECRET);
      expect(text).not.toContain(TOKEN_A);
      expect(text).not.toContain(NO_LIFETIME);
      expect(text).not.toContain("sig-");
    });

    it("writes nothing to the console on success or failure", async () => {
      const spies = (["log", "info", "warn", "error", "debug"] as const).map((m) =>
        jest.spyOn(console, m).mockImplementation(() => undefined)
      );
      try {
        const { now } = clock(T0);
        await createCentralM2MTokenSource({
          url: URL_,
          secret: SECRET,
          fetch: script(ok(TOKEN_A)).fetchMock,
          now,
        }).getToken();
        await createCentralM2MTokenSource({
          url: URL_,
          secret: SECRET,
          fetch: script(status(401)).fetchMock,
          now,
        })
          .getToken()
          .catch(() => undefined);
        for (const spy of spies) expect(spy).not.toHaveBeenCalled();
      } finally {
        for (const spy of spies) spy.mockRestore();
      }
    });
  });
});
