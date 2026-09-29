// Canned spec-vector routes (spec/vectors/*.json), served ahead of the real OP.
//
//   {ISSUER}/v/{run}/{capability}/{case_id}/{vector}/{path}  -> canned response
//   {ISSUER}/v/{run}/{capability}/{case_id}/{vector}/_check  -> request check
//
// The canned response is vector.http[path], or the n-th entry of
// vector.http_sequence[path] for the n-th request (the last one repeats).
// _check compares what was received against expect_request and expect_calls.
//
// {vector} is the vector's name, or its index when unnamed. {run} is any token
// the caller picks so concurrent runs of the same vector keep separate request
// records. https://server.example.com in a fixture is rewritten to the vector's
// base URL, so discovery documents point back here.

import fs from "node:fs";
import path from "node:path";

const FIXTURE_HOST = "https://server.example.com";
const ROUTE = /^\/v\/([\w.-]+)\/([a-z0-9-]+)\/([\w.-]+)\/([\w.-]+)(\/.*)$/;

function loadVector(specDir, capability, caseId, vectorKey) {
  const file = path.join(specDir, "vectors", `${capability}.json`);
  const spec = JSON.parse(fs.readFileSync(file, "utf8"));
  const tc = spec.tests.find((t) => t.id === caseId);
  if (!tc) return undefined;
  const vectors = tc.vectors || [];
  return (
    vectors.find((v) => v.name === vectorKey) ||
    (/^\d+$/.test(vectorKey) && !vectors[+vectorKey]?.name
      ? vectors[+vectorKey]
      : undefined)
  );
}

function readFixture(specDir, relPath) {
  const root = path.resolve(specDir, "test-fixtures");
  const file = path.resolve(root, relPath);
  if (!file.startsWith(root + path.sep)) {
    throw new Error(`fixture outside test-fixtures: ${relPath}`);
  }
  return fs.readFileSync(file, "utf8");
}

async function readBody(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf8");
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
      if (have !== undefined) diffs.push(`${label}header ${name} = ${JSON.stringify(have)}, want absent`);
      continue;
    }
    if (have !== undefined && name.toLowerCase() === "content-type") {
      have = have.split(";")[0].trim();
    }
    if (have !== value) diffs.push(`${label}header ${name} = ${JSON.stringify(have ?? null)}, want ${JSON.stringify(value)}`);
  }
  for (const [name, value] of Object.entries(want.form || {})) {
    if (value === "") {
      if (got.form.has(name)) diffs.push(`${label}form ${name} = ${JSON.stringify(got.form.get(name))}, want absent`);
      continue;
    }
    const have = got.form.get(name);
    if (have !== value) diffs.push(`${label}form ${name} = ${JSON.stringify(have)}, want ${JSON.stringify(value)}`);
  }
  return diffs;
}

// Compares the recorded requests (path -> list, in order) against
// expect_calls, and every request to expect_request.path against
// expect_request.
function check(vector, seen) {
  const diffs = [];
  for (const [p, count] of Object.entries(vector.expect_calls || {})) {
    const have = seen.get(p)?.length ?? 0;
    if (have !== count) diffs.push(`requests to ${p} = ${have}, want ${count}`);
  }
  const want = vector.expect_request;
  if (!want) return diffs;
  const got = seen.get(want.path) || [];
  if (got.length === 0) return [...diffs, `no request to ${want.path}`];
  got.forEach((req, i) => {
    diffs.push(...checkRequest(want, req, got.length > 1 ? `request ${i + 1}: ` : ""));
  });
  return diffs;
}

export function vectorRoutes({ issuer, specDir }) {
  const requests = new Map(); // base path -> Map(request path -> [recorded request])

  return async (ctx, next) => {
    const m = ROUTE.exec(ctx.path);
    if (!m) return next();
    const [, , capability, caseId, vectorKey, subPath] = m;
    const basePath = ctx.path.slice(0, ctx.path.length - subPath.length);

    let vector;
    try {
      vector = loadVector(specDir, capability, caseId, vectorKey);
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

    if (subPath === "/_check") {
      const diffs = check(vector, requests.get(basePath) || new Map());
      requests.delete(basePath);
      ctx.body = { ok: diffs.length === 0, diffs };
      return;
    }

    const body = await readBody(ctx.req);
    if (!requests.has(basePath)) requests.set(basePath, new Map());
    const seen = requests.get(basePath);
    if (!seen.has(subPath)) seen.set(subPath, []);
    seen.get(subPath).push({
      method: ctx.method,
      headers: { ...ctx.headers },
      form: new URLSearchParams(body),
    });
    const count = seen.get(subPath).length;

    const sequence = vector.http_sequence?.[subPath];
    const resp = sequence
      ? sequence[Math.min(count, sequence.length) - 1]
      : vector.http?.[subPath];
    if (!resp) {
      ctx.status = 404;
      return;
    }
    let payload = "";
    if (resp.body_fixture) {
      try {
        payload = readFixture(specDir, resp.body_fixture).replaceAll(
          FIXTURE_HOST,
          issuer + basePath,
        );
      } catch (err) {
        ctx.status = 500;
        ctx.body = { error: `body_fixture ${resp.body_fixture}: ${err.message}` };
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
