/**
 * @file A JSON reader that refuses a key named twice in one object.
 *
 * `JSON.parse` lets the last value of a repeated key win, so
 * `{"sub":"a","sub":"b"}` is user b. A strict reader refuses that body, so the
 * identity would depend on which parser read it (clerk-client#6,
 * meta fixture version 5). navigation-service's Java client parses with
 * Jackson's `STRICT_DUPLICATE_DETECTION`, which refuses a repeated key in any
 * object at any depth; agent-service's Go client refuses one among the
 * top-level members (and, like the Java client, a top-level repeat that
 * differs only in case). This reader refuses an exact repeat at any depth,
 * as Jackson does: a body that names a key twice is not one we can say we
 * understood, wherever the repeat sits. The top-level case rule (fixture
 * version 6) is applied after it, in center.ts, because it is about the
 * contract's keys and not about JSON.
 *
 * Otherwise it accepts exactly what `JSON.parse` accepts and builds the same
 * values: RFC 8259 grammar, the four whitespace characters, no trailing
 * commas, no comments, no trailing bytes. Keys are compared after their
 * escapes are decoded, so `"sub"` and `"s\u0075b"` are the same key. Every key
 * becomes an own data property, `__proto__` included, exactly as with
 * `JSON.parse`; no key reaches a prototype.
 *
 * It throws `SyntaxError` on anything it refuses. It is only ever handed a
 * body already read under the response cap (64 KiB by default).
 */

/**
 * Deeper than any center answer could be. Jackson's default nesting limit is
 * 1000 too; the cap keeps a body of brackets from exhausting the stack, which
 * would otherwise be a RangeError that depends on the host.
 */
const MAX_DEPTH = 1000;

const isDigit = (c: string | undefined): boolean => c !== undefined && c >= "0" && c <= "9";

const ESCAPES: Readonly<Record<string, string>> = {
  '"': '"',
  "\\": "\\",
  "/": "/",
  b: "\b",
  f: "\f",
  n: "\n",
  r: "\r",
  t: "\t",
};

class Reader {
  private pos = 0;

  constructor(private readonly text: string) {}

  document(): unknown {
    const value = this.value(0);
    this.skipWhitespace();
    if (this.pos !== this.text.length) this.fail("unexpected data after the value");
    return value;
  }

  private fail(what: string): never {
    throw new SyntaxError(`${what} at position ${this.pos}`);
  }

  private skipWhitespace(): void {
    for (;;) {
      const c = this.text[this.pos];
      if (c !== " " && c !== "\t" && c !== "\n" && c !== "\r") return;
      this.pos += 1;
    }
  }

  private expect(c: string): void {
    if (this.text[this.pos] !== c) this.fail(`expected '${c}'`);
    this.pos += 1;
  }

  private value(depth: number): unknown {
    this.skipWhitespace();
    const c = this.text[this.pos];
    if (c === "{") return this.object(depth + 1);
    if (c === "[") return this.array(depth + 1);
    if (c === '"') return this.string();
    if (c === "-" || isDigit(c)) return this.number();
    if (this.text.startsWith("true", this.pos)) return this.literal("true", true);
    if (this.text.startsWith("false", this.pos)) return this.literal("false", false);
    if (this.text.startsWith("null", this.pos)) return this.literal("null", null);
    return this.fail("expected a value");
  }

  private literal<T>(word: string, value: T): T {
    this.pos += word.length;
    return value;
  }

  private object(depth: number): Record<string, unknown> {
    if (depth > MAX_DEPTH) this.fail("nested too deeply");
    this.expect("{");
    const result: Record<string, unknown> = {};
    // Decoded keys, so an escaped spelling of a key is the same key.
    const seen = new Set<string>();
    this.skipWhitespace();
    if (this.text[this.pos] === "}") {
      this.pos += 1;
      return result;
    }
    for (;;) {
      this.skipWhitespace();
      if (this.text[this.pos] !== '"') this.fail("expected a string key");
      const key = this.string();
      if (seen.has(key)) this.fail("duplicate key");
      seen.add(key);
      this.skipWhitespace();
      this.expect(":");
      // defineProperty, not assignment: `result["__proto__"] = v` would set
      // the prototype instead of creating a key.
      Object.defineProperty(result, key, {
        value: this.value(depth),
        writable: true,
        enumerable: true,
        configurable: true,
      });
      this.skipWhitespace();
      if (this.text[this.pos] === ",") {
        this.pos += 1;
        continue;
      }
      this.expect("}");
      return result;
    }
  }

  private array(depth: number): unknown[] {
    if (depth > MAX_DEPTH) this.fail("nested too deeply");
    this.expect("[");
    const result: unknown[] = [];
    this.skipWhitespace();
    if (this.text[this.pos] === "]") {
      this.pos += 1;
      return result;
    }
    for (;;) {
      result.push(this.value(depth));
      this.skipWhitespace();
      if (this.text[this.pos] === ",") {
        this.pos += 1;
        continue;
      }
      this.expect("]");
      return result;
    }
  }

  private string(): string {
    this.expect('"');
    let out = "";
    let runStart = this.pos;
    for (;;) {
      const c = this.text[this.pos];
      if (c === undefined) this.fail("unterminated string");
      if (c === '"') {
        out += this.text.slice(runStart, this.pos);
        this.pos += 1;
        return out;
      }
      if (c < " ") this.fail("control character in a string");
      if (c !== "\\") {
        this.pos += 1;
        continue;
      }
      out += this.text.slice(runStart, this.pos);
      const escape = this.text[this.pos + 1];
      if (escape === "u") {
        const hex = this.text.slice(this.pos + 2, this.pos + 6);
        if (!/^[0-9a-fA-F]{4}$/.test(hex)) this.fail("bad unicode escape");
        // One UTF-16 unit per escape; a surrogate pair is two escapes, and a
        // lone surrogate is kept as JSON.parse keeps it.
        out += String.fromCharCode(parseInt(hex, 16));
        this.pos += 6;
      } else {
        const decoded = escape === undefined ? undefined : ESCAPES[escape];
        if (decoded === undefined) this.fail("bad escape");
        out += decoded;
        this.pos += 2;
      }
      runStart = this.pos;
    }
  }

  private number(): number {
    const start = this.pos;
    if (this.text[this.pos] === "-") this.pos += 1;
    if (this.text[this.pos] === "0") {
      this.pos += 1;
    } else if (isDigit(this.text[this.pos])) {
      while (isDigit(this.text[this.pos])) this.pos += 1;
    } else {
      this.fail("expected a digit");
    }
    if (this.text[this.pos] === ".") {
      this.pos += 1;
      if (!isDigit(this.text[this.pos])) this.fail("expected a digit");
      while (isDigit(this.text[this.pos])) this.pos += 1;
    }
    if (this.text[this.pos] === "e" || this.text[this.pos] === "E") {
      this.pos += 1;
      if (this.text[this.pos] === "+" || this.text[this.pos] === "-") this.pos += 1;
      if (!isDigit(this.text[this.pos])) this.fail("expected a digit");
      while (isDigit(this.text[this.pos])) this.pos += 1;
    }
    // The grammar above is JSON's, so Number() reads the same double
    // JSON.parse would, including Infinity for an exponent out of range.
    return Number(this.text.slice(start, this.pos));
  }
}

/**
 * Parse `text` as JSON, refusing a key repeated within any one object.
 *
 * @throws SyntaxError for anything `JSON.parse` refuses, for a repeated key,
 *   and for nesting deeper than {@link MAX_DEPTH}.
 */
export const parseStrictJson = (text: string): unknown => new Reader(text).document();
