// Canned spec-vector routes (spec/vectors/*.json), served ahead of the real OP.
//
//   {ISSUER}/v/{run}/{capability}/{case_id}/{vector}/{path}  -> canned response
//   {ISSUER}/v/{run}/{capability}/{case_id}/{vector}/_check  -> request check
//   {ISSUER}/v/{run}/{capability}/{case_id}/{vector}/_reset  -> POST to reset
//
// The canned response is vector.http[path], or the n-th entry of
// vector.http_sequence[path] for the n-th request (the last one repeats).
// _check compares what was received against expect_request and expect_calls,
// without clearing records or rewinding sequences. POST _reset does both.
// Request positions are reserved on arrival; _check fails while bodies remain
// pending, even when the received call count already matches.
//
// {vector} is the vector's name, or its index when unnamed. {run} must be a
// unique token of [A-Za-z0-9_.-] per suite invocation, including concurrent
// language suites. Both https://server.example.com and
// https://provider.example.com are rewritten to the vector's base URL.
// Records expire after 10 minutes of inactivity; use a fresh run token after
// expiry. Limits: 256 vector runs, 64 requests/run, 16 KiB/request body.
// Fixture and per-run limit errors also fail _check until POST _reset.

import fs from "node:fs";
import path from "node:path";
import Ajv from "ajv";

const FIXTURE_HOSTS =
  /https:\/\/(?:server|provider)\.example\.com(?=[/"\s?#]|$)/g;
const ROUTE = /^\/v\/([\w.-]+)\/([a-z0-9-]+)\/([\w.-]+)\/([\w.-]+)(\/.*)$/;

function requireValid(validate, value, label) {
  if (!validate(value)) {
    const errors = validate.errors.map(
      ({ instancePath, message }) => `${instancePath || "/"} ${message}`,
    );
    throw new Error(`invalid ${label}: ${errors.join("; ")}`);
  }
  return value;
}

function uniqueIndex(items, keyFor, label) {
  const indexed = new Map();
  items.forEach((item, index) => {
    const key = keyFor(item, index);
    if (indexed.has(key)) throw new Error(`${label}: duplicate key ${key}`);
    indexed.set(key, item);
  });
  return indexed;
}

function loadVector(specDir, validators, capability, caseId, vectorKey) {
  const file = path.join(specDir, "vectors", `${capability}.json`);
  const spec = requireValid(
    validators.file,
    JSON.parse(fs.readFileSync(file, "utf8")),
    `${capability}.json`,
  );
  const cases = uniqueIndex(spec.tests, (test) => test.id, `${capability}.json`);
  const tc = cases.get(caseId);
  if (!tc) return undefined;
  const vectors = uniqueIndex(
    tc.vectors ?? [],
    (vector, index) => vector.name ?? String(index),
    `${capability}/${caseId}`,
  );
  const vector = vectors.get(vectorKey);
  if (!vector) return undefined;
  requireValid(validators.http, vector, `${capability}/${caseId}/${vectorKey}`);
  const overlapping = Object.keys(vector.http || {}).filter(
    (requestPath) => Object.hasOwn(vector.http_sequence || {}, requestPath),
  );
  if (overlapping.length) {
    throw new Error(
      `${capability}/${caseId}/${vectorKey}: paths in both http and http_sequence: ${overlapping.join(", ")}`,
    );
  }
  return vector;
}

function readFixture(specDir, relPath) {
  const root = path.resolve(specDir, "test-fixtures");
  const file = path.resolve(root, relPath);
  if (!file.startsWith(root + path.sep)) {
    throw new Error(`fixture outside test-fixtures: ${relPath}`);
  }
  return fs.readFileSync(file, "utf8");
}

function readBody(req, maxBytes) {
  return new Promise((resolve, reject) => {
    let chunks = [];
    let size = 0;
    // Keep draining after rejecting so a chunked request gets a 413 response,
    // rather than destroying its socket as an early async-iterator exit does.
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > maxBytes) {
        chunks = [];
        reject(
          Object.assign(new Error(`request body exceeds ${maxBytes} bytes`), {
            status: 413,
          }),
        );
      } else {
        chunks.push(chunk);
      }
    });
    req.once("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.once("error", reject);
    req.once("aborted", () => reject(new Error("request aborted")));
  });
}

// Compares one recorded request against expect_request. An expected "" header
// or form value means the field must be absent.
function checkRequest(want, got, label) {
  const diffs = [];
  if (got.method !== want.method) {
    diffs.push(`${label}method = ${got.method}, want ${want.method}`);
  }
  for (const [name, value] of Object.entries(want.headers || {})) {
    let have = got.headers[name.toLowerCase()];
    if (value === "") {
      if (have !== undefined)
        diffs.push(
          `${label}header ${name} = ${JSON.stringify(have)}, want absent`,
        );
      continue;
    }
    if (have !== undefined && name.toLowerCase() === "content-type") {
      have = have.split(";")[0].trim();
    }
    if (have !== value)
      diffs.push(
        `${label}header ${name} = ${JSON.stringify(have ?? null)}, want ${JSON.stringify(value)}`,
      );
  }
  for (const [name, value] of Object.entries(want.form || {})) {
    if (value === "") {
      if (got.form.has(name))
        diffs.push(
          `${label}form ${name} = ${JSON.stringify(got.form.get(name))}, want absent`,
        );
      continue;
    }
    const have = got.form.getAll(name);
    if (have.length !== 1 || have[0] !== value)
      diffs.push(
        `${label}form ${name} = ${JSON.stringify(have)}, want exactly one ${JSON.stringify(value)}`,
      );
  }
  return diffs;
}

// Compares the recorded requests (path -> list, in order) against
// expect_calls, and every request to expect_request.path against
// expect_request.
function check(vector, seen) {
  const diffs = [];
  for (const [p, records] of seen) {
    const pending = records.filter((req) => req.pending).length;
    if (pending) diffs.push(`requests to ${p}: ${pending} body pending`);
  }
  for (const [p, count] of Object.entries(vector.expect_calls || {})) {
    const have = seen.get(p)?.length ?? 0;
    if (have !== count) diffs.push(`requests to ${p} = ${have}, want ${count}`);
  }
  const want = vector.expect_request;
  if (!want) return diffs;
  const got = seen.get(want.path) || [];
  if (got.length === 0) return [...diffs, `no request to ${want.path}`];
  got.forEach((req, i) => {
    if (req.pending) return;
    diffs.push(
      ...checkRequest(want, req, got.length > 1 ? `request ${i + 1}: ` : ""),
    );
  });
  return diffs;
}

export function vectorRoutes({
  issuer,
  specDir,
  maxBodyBytes = 16 * 1024,
  maxRuns = 256,
  maxRequests = 64,
  ttlMs = 10 * 60 * 1000,
}) {
  const schema = JSON.parse(
    fs.readFileSync(path.join(specDir, "http-vector.schema.json"), "utf8"),
  );
  const ajv = new Ajv({ strict: true, allErrors: true, ownProperties: true });
  const validators = {
    http: ajv.compile(schema),
    file: ajv.compile({ $ref: `${schema.$id}#/definitions/vectorFile` }),
  };
  const requests = new Map(); // base path -> { seen, count, updatedAt, error }

  return async (ctx, next) => {
    const m = ROUTE.exec(ctx.path);
    if (!m) return next();
    const [, , capability, caseId, vectorKey, subPath] = m;
    const basePath = ctx.path.slice(0, ctx.path.length - subPath.length);

    let vector;
    try {
      vector = loadVector(specDir, validators, capability, caseId, vectorKey);
    } catch (err) {
      ctx.status = err.code === "ENOENT" ? 404 : 500;
      ctx.body = { error: `load ${capability}.json: ${err.message}` };
      return;
    }
    if (!vector) {
      ctx.status = 404;
      ctx.body = { error: `no vector ${capability}/${caseId}/${vectorKey}` };
      return;
    }

    if (subPath === "/_reset") {
      if (ctx.method !== "POST") {
        ctx.status = 405;
        ctx.set("Allow", "POST");
        return;
      }
      requests.delete(basePath);
      ctx.body = { ok: true };
      return;
    }

    const now = Date.now();
    for (const [key, run] of requests) {
      if (now - run.updatedAt >= ttlMs) requests.delete(key);
    }
    let run = requests.get(basePath);
    if (!run && requests.size >= maxRuns) {
      ctx.status = 503;
      ctx.body = {
        error: `vector run limit ${maxRuns} reached; reset completed runs`,
      };
      return;
    }
    if (subPath === "/_check") {
      const diffs = check(vector, run?.seen || new Map());
      if (run) {
        run.updatedAt = now;
        if (run.error) diffs.unshift(run.error);
      } else if (
        !vector.expect_calls ||
        vector.expect_request ||
        Object.values(vector.expect_calls).some((count) => count !== 0)
      ) {
        diffs.unshift(
          "no recorded run (unused, reset or expired); use a fresh run token",
        );
      }
      ctx.body = { ok: diffs.length === 0, diffs };
      return;
    }

    if (!run) {
      run = { seen: new Map(), count: 0, updatedAt: now };
      requests.set(basePath, run);
    }
    run.updatedAt = now;
    if (run.count >= maxRequests) {
      run.error ||= `request limit ${maxRequests} reached`;
      ctx.status = 429;
      ctx.body = { error: run.error };
      return;
    }
    // Reserve a slot before awaiting the body, including concurrent requests.
    run.count += 1;
    const seen = run.seen;
    if (!seen.has(subPath)) seen.set(subPath, []);
    const record = {
      method: ctx.method,
      headers: { ...ctx.headers },
      form: new URLSearchParams(),
      pending: true,
    };
    seen.get(subPath).push(record);
    const count = seen.get(subPath).length;
    let body;
    try {
      body = await readBody(ctx.req, maxBodyBytes);
    } catch (err) {
      record.pending = false;
      run.error ||= err.message;
      ctx.status = err.status ?? 400;
      ctx.body = { error: err.message };
      return;
    }
    record.form = new URLSearchParams(body);
    record.pending = false;

    const sequence = vector.http_sequence?.[subPath];
    const resp = sequence
      ? sequence[Math.min(count, sequence.length) - 1]
      : vector.http?.[subPath];
    if (!resp) {
      run.error ||= `no canned response for ${subPath}`;
      ctx.status = 404;
      return;
    }
    let payload = "";
    if (resp.body_fixture) {
      try {
        payload = readFixture(specDir, resp.body_fixture).replace(
          FIXTURE_HOSTS,
          () => issuer + basePath,
        );
      } catch (err) {
        const error = `${capability}/${caseId}/${vectorKey}: body_fixture ${resp.body_fixture}: ${err.message}`;
        run.error ||= error;
        ctx.status = err.code === "ENOENT" ? 404 : 500;
        ctx.body = { error };
        return;
      }
    }
    for (const [name, value] of Object.entries(resp.headers || {})) {
      ctx.set(name, value);
    }
    if (payload && !ctx.response.get("Content-Type")) {
      ctx.type = "application/json";
    }
    // Body before status: a null body would otherwise turn the status into 204.
    ctx.body = payload || null;
    ctx.status = resp.status ?? 200;
  };
}
