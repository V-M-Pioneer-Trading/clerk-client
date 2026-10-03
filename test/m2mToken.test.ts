/**
 * @file The caller side of the center's machine-token endpoint.
 *
 * `fetch` and the clock are injected, so each test states exactly what the
 * center said and what time it is.
 */

import { createCentralM2MTokenSource, M2MTokenError } from "../src";
import type { M2MTokenErrorKind } from "../src";

const URL_ = "http://localhost:3005/auth/v1/m2m-token";
const SECRET = "caller-secret-do-not-leak";
const T0 = 1_790_000_000; // seconds, about now; the token's iat
const LIFETIME = 86_400;
const HALF = LIFETIME / 2;
const SPACING = 10; // seconds

const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
const jwt = (claims: Record<string, unknown>, tag: string): string =>
  `${b64({ alg: "RS256" })}.${b64({ sub: "mch_x", ...claims })}.sig-${tag}`;
const lived = (iat: number, exp: number, tag: string): string => jwt({ iat, exp }, tag);

const TOKEN_A = lived(T0, T0 + LIFETIME, "A");
const TOKEN_B = lived(T0 + HALF, T0 + HALF + LIFETIME, "B");

/** The center's 200: expires_at is the token's own exp, as the contract says. */
const ok = (token: string): Response => {
  const exp = (JSON.parse(Buffer.from(token.split(".")[1] ?? "", "base64url").toString()) as { exp?: number }).exp;
  return new Response(JSON.stringify({ token, expires_at: exp }), { status: 200 });
};
const status = (code: number): Response => new Response(JSON.stringify({ error: "x" }), { status: code });
const timeout = (): Error =>
  Object.assign(new Error("The operation was aborted due to timeout"), { name: "TimeoutError" });
/** A 200 whose body never finishes in time. */
const bodyTimeout = (): Response =>
  ({ status: 200, body: null, json: () => Promise.reject(timeout()) }) as unknown as Response;

type Step = Response | Error;
const script = (...steps: Step[]) => {
  const calls: { url: string; init: RequestInit }[] = [];
  const fetchMock = ((url: string, init: RequestInit) => {
    calls.push({ url, init });
    const step = steps.shift();
    if (step === undefined) return Promise.reject(new Error("unscripted call"));
    if (step instanceof Error) return Promise.reject(step);
    return Promise.resolve(step);
  }) as unknown as typeof fetch;
  return { calls, fetchMock };
};

const clock = (seconds: number) => {
  const c = { seconds };
  return { c, now: () => c.seconds * 1000 };
};

const build = (steps: Step[], at = T0) => {
  const { calls, fetchMock } = script(...steps);
  const { c, now } = clock(at);
  const source = createCentralM2MTokenSource({ url: URL_, secret: SECRET, fetch: fetchMock, now });
  return { calls, c, source };
};

const failure = async (p: Promise<unknown>): Promise<M2MTokenError> => {
  const err = await p.then(
    () => null,
    (e: unknown) => e
  );
  expect(err).toBeInstanceOf(M2MTokenError);
  return err as M2MTokenError;
};
const kindOf = async (p: Promise<unknown>): Promise<M2MTokenErrorKind> => (await failure(p)).kind;

describe("createCentralM2MTokenSource", () => {
  it("POSTs with the secret header, an empty body and a timeout signal, and returns the token", async () => {
    const { calls, source } = build([ok(TOKEN_A)]);

    await expect(source.getToken()).resolves.toBe(TOKEN_A);

    expect(calls).toHaveLength(1);
    const call = calls[0];
    expect(call).toBeDefined();
    expect(call?.url).toBe(URL_);
    expect(call?.init.method).toBe("POST");
    expect(call?.init.headers).toEqual({ "X-M2M-Caller-Secret": SECRET });
    expect(call?.init.body).toBeUndefined();
    expect(call?.init.signal).toBeInstanceOf(AbortSignal);
  });

  it("serves the cache before the refresh point iat + (exp - iat) / 2 and refreshes at it", async () => {
    const { calls, c, source } = build([ok(TOKEN_A), ok(TOKEN_B)]);

    await source.getToken();
    c.seconds = T0 + HALF - 1;
    await expect(source.getToken()).resolves.toBe(TOKEN_A);
    expect(calls).toHaveLength(1);

    c.seconds = T0 + HALF;
    await expect(source.getToken()).resolves.toBe(TOKEN_B);
    expect(calls).toHaveLength(2);
    await expect(source.getToken()).resolves.toBe(TOKEN_B);
    expect(calls).toHaveLength(2);
  });

  it("measures the refresh point from iat, not from the moment the token arrived", async () => {
    // Served 10 h after it was minted: 2 h of its first half remain.
    const late = T0 + 10 * 3600;
    const { calls, c, source } = build([ok(TOKEN_A), ok(TOKEN_B)], late);
    await source.getToken();
    c.seconds = T0 + HALF - 1;
    await source.getToken();
    expect(calls).toHaveLength(1);
    c.seconds = T0 + HALF;
    await source.getToken();
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

  describe("a failed refresh", () => {
    it("serves the cached token while it is unexpired", async () => {
      const { calls, c, source } = build([ok(TOKEN_A), status(503)]);
      await source.getToken();
      c.seconds = T0 + HALF + 1;
      await expect(source.getToken()).resolves.toBe(TOKEN_A);
      expect(calls).toHaveLength(2);
    });

    it("is not repeated for 10 s: the cached token comes back with no request", async () => {
      const { calls, c, source } = build([ok(TOKEN_A), status(503), ok(TOKEN_B)]);
      await source.getToken();
      c.seconds = T0 + HALF + 1;
      await source.getToken(); // the failed refresh, at T0 + HALF + 1
      expect(calls).toHaveLength(2);

      c.seconds = T0 + HALF + 1 + SPACING - 1;
      await expect(source.getToken()).resolves.toBe(TOKEN_A);
      expect(calls).toHaveLength(2);

      c.seconds = T0 + HALF + 1 + SPACING;
      await expect(source.getToken()).resolves.toBe(TOKEN_B);
      expect(calls).toHaveLength(3);
    });

    it("throws once the cached token has expired, and within the window without a request", async () => {
      const { calls, c, source } = build([ok(TOKEN_A), status(503), status(503)]);
      await source.getToken();
      c.seconds = T0 + LIFETIME;
      expect(await kindOf(source.getToken())).toBe("unavailable");
      expect(calls).toHaveLength(2);

      c.seconds += SPACING - 1;
      expect(await kindOf(source.getToken())).toBe("unavailable");
      expect(calls).toHaveLength(2);

      c.seconds += 1;
      expect(await kindOf(source.getToken())).toBe("unavailable");
      expect(calls).toHaveLength(3);
    });

    it("also spaces out a failed first fetch", async () => {
      const { calls, c, source } = build([status(503), ok(TOKEN_A)]);
      expect(await kindOf(source.getToken())).toBe("unavailable");
      c.seconds = T0 + SPACING - 1;
      expect(await kindOf(source.getToken())).toBe("unavailable");
      expect(calls).toHaveLength(1);
      c.seconds = T0 + SPACING;
      await expect(source.getToken()).resolves.toBe(TOKEN_A);
    });
  });

  describe("retry", () => {
    it("retries once, immediately, after a timeout", async () => {
      const { calls, source } = build([timeout(), ok(TOKEN_A)]);
      await expect(source.getToken()).resolves.toBe(TOKEN_A);
      expect(calls).toHaveLength(2);
    });

    it("retries a timeout while reading the body, and reports it as a timeout", async () => {
      const ok1 = build([bodyTimeout(), ok(TOKEN_A)]);
      await expect(ok1.source.getToken()).resolves.toBe(TOKEN_A);
      expect(ok1.calls).toHaveLength(2);

      const bad = build([bodyTimeout(), bodyTimeout(), ok(TOKEN_A)]);
      const err = await failure(bad.source.getToken());
      expect(bad.calls).toHaveLength(2);
      expect(err.kind).toBe("unavailable");
      expect(err.message).toMatch(/in time/);
      expect(err.cause).toEqual({ name: "TimeoutError" });
    });

    it("retries only once: two timeouts fail with exactly two requests", async () => {
      const { calls, source } = build([timeout(), timeout(), ok(TOKEN_A)]);
      const err = await failure(source.getToken());
      expect(err.kind).toBe("unavailable");
      expect(err.cause).toEqual({ name: "TimeoutError" });
      expect(calls).toHaveLength(2);
    });

    it("does not retry a 503", async () => {
      const { calls, source } = build([status(503), ok(TOKEN_A)]);
      expect(await kindOf(source.getToken())).toBe("unavailable");
      expect(calls).toHaveLength(1);
    });

    it("does not retry a 401", async () => {
      const { calls, source } = build([status(401), ok(TOKEN_A)]);
      await expect(source.getToken()).rejects.toThrow(/did not recognise this caller/);
      expect(calls).toHaveLength(1);
    });

    it("does not retry a refused connection", async () => {
      const { calls, source } = build([
        Object.assign(new TypeError("fetch failed"), { cause: { code: "ECONNREFUSED" } }),
        ok(TOKEN_A),
      ]);
      expect(await kindOf(source.getToken())).toBe("unavailable");
      expect(calls).toHaveLength(1);
    });
  });

  describe("a 401", () => {
    it("is unknown-caller", async () => {
      const { source } = build([status(401)]);
      expect(await kindOf(source.getToken())).toBe("unknown-caller");
    });

    it("surfaces even when a cached token is still valid", async () => {
      const { c, source } = build([ok(TOKEN_A), status(401)]);
      await source.getToken();
      c.seconds = T0 + HALF + 1;
      expect(await kindOf(source.getToken())).toBe("unknown-caller");
    });

    it("keeps surfacing inside the 10 s window, without another request", async () => {
      const { calls, c, source } = build([ok(TOKEN_A), status(401), ok(TOKEN_B)]);
      await source.getToken();
      c.seconds = T0 + HALF + 1;
      await kindOf(source.getToken());
      c.seconds += 1;
      expect(await kindOf(source.getToken())).toBe("unknown-caller");
      expect(calls).toHaveLength(2);
    });
  });

  describe("error kinds", () => {
    it("503 is unavailable", async () => {
      expect(await kindOf(build([status(503)]).source.getToken())).toBe("unavailable");
    });

    it("any other status is unavailable", async () => {
      expect(await kindOf(build([status(500)]).source.getToken())).toBe("unavailable");
    });

    it("a transport failure is unavailable, and its cause carries only code and name", async () => {
      const boom = Object.assign(new TypeError(`fetch failed ${SECRET} ${TOKEN_A}`), {
        cause: { code: "ECONNREFUSED", message: SECRET },
      });
      const err = await failure(build([boom]).source.getToken());
      expect(err.kind).toBe("unavailable");
      expect(err.cause).toEqual({ code: "ECONNREFUSED", name: "TypeError" });
    });

    it("drops a code or name that is not a short identifier", async () => {
      const boom = Object.assign(new Error("x"), { name: `bad ${SECRET}`, code: TOKEN_A });
      const err = await failure(build([boom]).source.getToken());
      expect(err.cause).toEqual({});
    });

    it.each([
      ["a body that is not JSON", () => new Response("not json", { status: 200 })],
      ["a body that is not an object", () => new Response("null", { status: 200 })],
      ["a body with no token", () => new Response("{}", { status: 200 })],
      ["a token that is not a string", () => new Response('{"token":5}', { status: 200 })],
      ["a token that is not a JWT", () => new Response('{"token":"abc"}', { status: 200 })],
    ])("%s is malformed", async (_name, response) => {
      expect(await kindOf(build([response()]).source.getToken())).toBe("malformed");
    });

    it("an empty token is refused as an empty token, not as a bad JWT", async () => {
      const err = await failure(build([new Response('{"token":""}', { status: 200 })]).source.getToken());
      expect(err.kind).toBe("malformed");
      expect(err.message).toMatch(/without a token/);
    });
  });

  describe("lifetime sanity", () => {
    const tokenFailure = async (token: string): Promise<M2MTokenError> => {
      const err = await failure(build([ok(token)]).source.getToken());
      expect(err.kind).toBe("malformed");
      return err;
    };

    it.each([
      ["iat missing", { exp: T0 + LIFETIME }],
      ["exp missing", { iat: T0 }],
      ["iat a string", { iat: String(T0), exp: T0 + LIFETIME }],
      ["exp a string", { iat: T0, exp: String(T0 + LIFETIME) }],
      ["iat null", { iat: null, exp: T0 + LIFETIME }],
    ])("refuses %s", async (_name, claims) => {
      await tokenFailure(jwt(claims, "x"));
    });

    it("refuses a non-finite iat or exp", async () => {
      // JSON cannot carry Infinity or NaN, so the payload is written by hand:
      // 1e999 parses to Infinity.
      const payload = (text: string) => `e30.${Buffer.from(text).toString("base64url")}.sig-x`;
      await tokenFailure(payload(`{"iat":${String(T0)},"exp":1e999}`));
      await tokenFailure(payload(`{"iat":-1e999,"exp":${String(T0 + LIFETIME)}}`));
    });

    it("refuses exp equal to iat", async () => {
      await tokenFailure(lived(T0 + 100, T0 + 100, "x"));
    });

    it("refuses exp before iat, even though exp is still in the future", async () => {
      // Without the exp > iat rule this would be accepted: now < exp.
      const err = await tokenFailure(lived(T0 + 1000, T0 + 500, "x"));
      expect(err.message).toMatch(/implausible/);
    });

    it("refuses a lifetime over 7 days and accepts exactly 7", async () => {
      const week = 7 * 86_400;
      await tokenFailure(lived(T0, T0 + week + 1, "x"));
      await expect(build([ok(lived(T0, T0 + week, "week"))]).source.getToken()).resolves.toContain("sig-week");
    });

    it("refuses a token already expired by the local clock, and accepts one second before", async () => {
      const token = lived(T0 - 1000, T0 + 1000, "x");
      await expect(build([ok(token)], T0 + 1000 - 1).source.getToken()).resolves.toBe(token);
      const err = await failure(build([ok(token)], T0 + 1000).source.getToken());
      expect(err.kind).toBe("malformed");
      expect(err.message).toMatch(/already expired/);
    });
  });

  describe("construction", () => {
    const make = (over: Record<string, unknown>) => () =>
      createCentralM2MTokenSource({ url: URL_, secret: SECRET, ...over });

    it("accepts the minimal valid options and the extremes of timeoutMs", () => {
      expect(make({})).not.toThrow();
      expect(make({ timeoutMs: 1 })).not.toThrow();
      expect(make({ timeoutMs: 2 ** 31 - 1 })).not.toThrow();
    });

    it.each([
      ["an empty url", { url: "" }],
      ["a blank url", { url: "  " }],
      ["a missing url", { url: undefined }],
      ["an empty secret", { secret: "" }],
      ["a missing secret", { secret: undefined }],
      ["a secret with LF", { secret: "a\nb" }],
      ["a secret with CR", { secret: "a\rb" }],
      ["timeoutMs 0", { timeoutMs: 0 }],
      ["a negative timeoutMs", { timeoutMs: -5 }],
      ["a fractional timeoutMs", { timeoutMs: 1.5 }],
      ["a NaN timeoutMs", { timeoutMs: NaN }],
      ["an infinite timeoutMs", { timeoutMs: Infinity }],
      ["a string timeoutMs", { timeoutMs: "1000" }],
      ["timeoutMs over 2^31-1", { timeoutMs: 2 ** 31 }],
    ])("throws synchronously for %s", (_name, over) => {
      expect(make(over)).toThrow();
    });

    it("never echoes the secret when it refuses one", () => {
      try {
        make({ secret: `${SECRET}\nX-Evil: 1` })();
        throw new Error("should have thrown");
      } catch (err) {
        expect((err as Error).message).not.toContain(SECRET);
      }
    });
  });

  describe("secrecy", () => {
    const failures: [string, Step[]][] = [
      ["a 401", [status(401)]],
      ["a 503", [status(503)]],
      ["two timeouts", [timeout(), timeout()]],
      ["a network error", [new Error(`connect ECONNREFUSED ${SECRET} ${TOKEN_A}`)]],
      ["an unexpected status", [status(500)]],
      ["a body with no token", [new Response("{}", { status: 200 })]],
      ["an empty token", [new Response('{"token":""}', { status: 200 })]],
      ["a token with no lifetime", [ok(jwt({ sub: "mch_x" }, "nolife"))]],
      ["a token with a bad lifetime", [ok(lived(T0, T0 + 30 * 86_400, "long"))]],
      ["an expired token", [ok(lived(T0 - 2000, T0 - 1000, "old"))]],
      ["a non-JSON body", [new Response(`${SECRET} ${TOKEN_A}`, { status: 200 })]],
    ];

    it.each(failures)("an error for %s carries neither the secret nor a token", async (_name, steps) => {
      const err = await failure(build(steps).source.getToken());
      const text = `${err.message}\n${err.stack ?? ""}\n${JSON.stringify(err.cause ?? null)}`;
      expect(text).not.toContain(SECRET);
      expect(text).not.toContain(TOKEN_A);
      expect(text).not.toContain("sig-");
    });

    it("writes nothing to the console on success or failure", async () => {
      const spies = (["log", "info", "warn", "error", "debug"] as const).map((m) =>
        jest.spyOn(console, m).mockImplementation(() => undefined)
      );
      try {
        await build([ok(TOKEN_A)]).source.getToken();
        await build([status(401)])
          .source.getToken()
          .catch(() => undefined);
        for (const spy of spies) expect(spy).not.toHaveBeenCalled();
      } finally {
        for (const spy of spies) spy.mockRestore();
      }
    });
  });
});
