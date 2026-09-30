import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { once } from "node:events";
import { test } from "node:test";
import Koa from "koa";
import { vectorRoutes } from "./vectors.js";

const response = (body_fixture = "first.json") => ({
  status: 200,
  body_fixture,
});
const basic = { name: "one", http: { "/token": response() } };

async function start(t, { vector = basic, spec, ...limits } = {}) {
  const specDir = fs.mkdtempSync(path.join(os.tmpdir(), "http-vectors-"));
  fs.mkdirSync(path.join(specDir, "vectors"));
  fs.mkdirSync(path.join(specDir, "test-fixtures"));
  fs.writeFileSync(
    path.join(specDir, "vectors/sample.json"),
    JSON.stringify(spec ?? { tests: [{ id: "CASE-1", vectors: [vector] }] }),
  );
  for (const [name, body] of Object.entries({
    "first.json": '{"step":1}',
    "second.json": '{"step":2}',
    "hosts.json":
      '{"issuer":"https://provider.example.com","jwks_uri":"https://server.example.com/jwks"}',
  }))
    fs.writeFileSync(path.join(specDir, "test-fixtures", name), body);
  const app = new Koa();
  app.silent = true;
  const server = http.createServer();
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const issuer = `http://127.0.0.1:${server.address().port}`;
  app.use(vectorRoutes({ issuer, specDir, ...limits }));
  app.use((ctx) => {
    ctx.body = "real provider";
  });
  server.on("request", app.callback());
  t.after(async () => {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
    fs.rmSync(specDir, { recursive: true, force: true });
  });
  const base = `${issuer}/v/run/sample/CASE-1/${vector.name ?? "0"}`;
  const request = (suffix, options) =>
    fetch(base + suffix, {
      signal: AbortSignal.timeout(5000),
      ...options,
    });
  const check = async () => (await request("/_check")).json();
  return { base, issuer, request, check, specDir };
}

test("checks are repeatable and do not rewind a response sequence", async (t) => {
  const { request, check } = await start(t, {
    vector: {
      name: "one",
      http_sequence: { "/token": [response(), response("second.json")] },
      expect_calls: { "/token": 1 },
    },
  });
  assert.deepEqual(await (await request("/token")).json(), { step: 1 });
  assert.deepEqual(await check(), { ok: true, diffs: [] });
  assert.deepEqual(await check(), { ok: true, diffs: [] });
  assert.deepEqual(await (await request("/token")).json(), { step: 2 });
  assert.deepEqual(await (await request("/token")).json(), { step: 2 });
  assert.equal((await check()).ok, false);
});

test("POST reset clears only this vector's records and sequence", async (t) => {
  const { base, request, check } = await start(t, {
    vector: {
      name: "one",
      http_sequence: { "/token": [response(), response("second.json")] },
      expect_calls: { "/token": 1 },
    },
  });
  await request("/token");
  const other = base.replace("/run/", "/other-run/");
  await fetch(other + "/token");
  assert.equal((await request("/_reset", { method: "POST" })).status, 200);
  assert.equal((await check()).ok, false);
  assert.deepEqual(await (await request("/token")).json(), { step: 1 });
  assert.deepEqual(await (await fetch(other + "/_check")).json(), {
    ok: true,
    diffs: [],
  });
});

test("GET reset cannot mutate request records", async (t) => {
  const { request, check } = await start(t, {
    vector: { ...basic, expect_calls: { "/token": 1 } },
  });
  await request("/token");
  const result = await request("/_reset");
  assert.equal(result.status, 405);
  assert.equal(result.headers.get("allow"), "POST");
  assert.deepEqual(await check(), { ok: true, diffs: [] });
});

test("checks the first request even when the last request matches", async (t) => {
  const { request, check } = await start(t, {
    vector: {
      ...basic,
      expect_calls: { "/token": 2 },
      expect_request: {
        path: "/token",
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        form: { token: "yes", absent: "" },
      },
    },
  });
  await request("/token");
  await request("/token", {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded; charset=utf-8",
    },
    body: "token=yes",
  });
  const result = await check();
  assert.equal(result.ok, false);
  assert.match(result.diffs.join("\n"), /request 1: method = GET/);
  assert.ok(result.diffs.every((diff) => diff.startsWith("request 1:")));
});

test("empty expected headers and form values require absence", async (t) => {
  const { request, check } = await start(t, {
    vector: {
      ...basic,
      expect_request: {
        path: "/token",
        method: "POST",
        headers: { "x-absent": "" },
        form: { absent: "" },
      },
    },
  });
  await request("/token", {
    method: "POST",
    headers: { "x-absent": "" },
    body: "absent=",
  });
  const result = await check();
  assert.equal(result.ok, false);
  assert.equal(result.diffs.length, 2);
  assert.ok(result.diffs.every((diff) => diff.includes("want absent")));
});

test("rewrites both fixture placeholder origins", async (t) => {
  const { base, request } = await start(t, {
    vector: { ...basic, http: { "/token": response("hosts.json") } },
  });
  assert.deepEqual(await (await request("/token")).json(), {
    issuer: base,
    jwks_uri: base + "/jwks",
  });
});

for (const [fixture, status] of [
  ["missing.json", 404],
  ["../vectors/sample.json", 500],
  ["/etc/passwd", 500],
]) {
  test(`fixture failure ${fixture} is attributed and fails the check`, async (t) => {
    const { request, check } = await start(t, {
      vector: { ...basic, http: { "/token": response(fixture) } },
    });
    const result = await request("/token");
    assert.equal(result.status, status);
    assert.match((await result.json()).error, /sample\/CASE-1\/one/);
    assert.equal((await check()).ok, false);
    assert.match((await check()).diffs.join("\n"), /body_fixture/);
  });
}

test("capability without tests and unknown vectors return 404", async (t) => {
  const { issuer, request } = await start(t, { spec: {} });
  assert.equal((await request("/token")).status, 404);
  assert.equal(
    (await fetch(issuer + "/v/run/unknown/CASE-1/one/token")).status,
    404,
  );
});

test("unknown cases, vector names and response paths return 404", async (t) => {
  const { base, request } = await start(t);
  assert.equal(
    (await fetch(base.replace("CASE-1", "CASE-2") + "/token")).status,
    404,
  );
  assert.equal(
    (await fetch(base.replace("/one", "/missing") + "/token")).status,
    404,
  );
  assert.equal((await request("/missing")).status, 404);
});

test("an unexpected path is recorded and fails zero-call expectations", async (t) => {
  const { request, check } = await start(t, {
    vector: { ...basic, expect_calls: { "/missing": 0 } },
  });
  assert.equal((await request("/missing")).status, 404);
  const result = await check();
  assert.equal(result.ok, false);
  assert.ok(result.diffs.includes("requests to /missing = 1, want 0"));
});

test("an unsupported path cannot pass a vector without assertions", async (t) => {
  const { request, check } = await start(t);
  await request("/missing");
  assert.equal((await check()).ok, false);
});

test("explicit zero-call expectations can pass without requests", async (t) => {
  const { check } = await start(t, {
    vector: { ...basic, expect_calls: { "/token": 0 } },
  });
  assert.deepEqual(await check(), { ok: true, diffs: [] });
});

test("unnamed vectors keep their original index", async (t) => {
  const { request } = await start(t, { vector: { http: basic.http } });
  assert.deepEqual(await (await request("/token")).json(), { step: 1 });
});

test("empty responses default to status 200", async (t) => {
  const { request } = await start(t, {
    vector: { ...basic, http: { "/token": {} } },
  });
  const result = await request("/token");
  assert.equal(result.status, 200);
  assert.equal(await result.text(), "");
});

test("non-vector routes pass through to the real provider", async (t) => {
  const { issuer } = await start(t);
  assert.equal(
    await (await fetch(issuer + "/.well-known/openid-configuration")).text(),
    "real provider",
  );
});

test("body byte limit rejects declared and chunked oversized bodies", async (t) => {
  const { base, request, check } = await start(t, { maxBodyBytes: 4 });
  assert.equal(
    (await request("/token", { method: "POST", body: "1234" })).status,
    200,
  );
  assert.equal(
    (await request("/token", { method: "POST", body: "12345" })).status,
    413,
  );
  const status = await new Promise((resolve, reject) => {
    const req = http.request(base + "/token", { method: "POST" }, (res) => {
      res.resume();
      resolve(res.statusCode);
    });
    req.on("error", reject);
    req.write("1234");
    req.end("5");
  });
  assert.equal(status, 413);
  assert.equal((await check()).ok, false);
});

test("record cap fails the check until explicit reset", async (t) => {
  const { request, check } = await start(t, { maxRequests: 1 });
  await request("/token");
  assert.equal((await request("/token")).status, 429);
  assert.equal((await check()).ok, false);
  await request("/_reset", { method: "POST" });
  assert.equal((await request("/token")).status, 200);
  assert.deepEqual(await check(), { ok: true, diffs: [] });
});

test("run cap preserves existing records and reset frees capacity", async (t) => {
  const { base, request, check } = await start(t, {
    maxRuns: 1,
    vector: { ...basic, expect_calls: { "/token": 1 } },
  });
  await request("/token");
  const other = base.replace("/run/", "/other/");
  assert.equal((await fetch(other + "/token")).status, 503);
  assert.equal((await fetch(other + "/_check")).status, 503);
  assert.deepEqual(await check(), { ok: true, diffs: [] });
  await request("/_reset", { method: "POST" });
  assert.equal((await fetch(other + "/token")).status, 200);
});

test("expired records release capacity and cannot silently pass a check", async (t) => {
  const { base, request, check } = await start(t, { maxRuns: 1, ttlMs: 10 });
  t.mock.timers.enable({ apis: ["Date"] });
  await request("/token");
  t.mock.timers.tick(11);
  assert.equal((await check()).ok, false);
  assert.equal(
    (await fetch(base.replace("/run/", "/other/") + "/token")).status,
    200,
  );
});
