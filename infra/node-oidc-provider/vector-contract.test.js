import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import Koa from "koa";
import { vectorRoutes } from "./vectors.js";

const basic = {
  name: "one",
  http: { "/token": {} },
  expect_request: { path: "/token", method: "POST", form: { token: "yes" } },
  expect_calls: { "/token": 1 },
};

// Exercise the real middleware and Koa context without a listening socket.
function fixture(t, { vector = basic, spec } = {}) {
  const specDir = fs.mkdtempSync(path.join(os.tmpdir(), "vector-contract-"));
  t.after(() => fs.rmSync(specDir, { recursive: true, force: true }));
  fs.mkdirSync(path.join(specDir, "vectors"));
  fs.copyFileSync(
    new URL("../../spec/http-vector.schema.json", import.meta.url),
    path.join(specDir, "http-vector.schema.json"),
  );
  fs.writeFileSync(
    path.join(specDir, "vectors/sample.json"),
    JSON.stringify(spec ?? { tests: [{ id: "CASE-1", vectors: [vector] }] }),
  );
  const app = new Koa();
  const routes = vectorRoutes({ issuer: "http://fixture", specDir });
  return (suffix, options) => dispatch(
    app, routes, `/v/run/sample/CASE-1/${vector.name ?? "0"}${suffix}`, options,
  );
}

async function dispatch(app, routes, url, { method = "GET", body = "", headers = {} } = {}) {
  const req = new http.IncomingMessage(new net.Socket());
  const res = new http.ServerResponse(req);
  req.url = url;
  req.method = method;
  req.headers = headers;
  const ctx = app.createContext(req, res);
  const handled = routes(ctx, () => assert.fail("vector route passed through"));
  req.push(Buffer.from(body));
  req.push(null);
  await handled;
  return ctx;
}

test("a single matching scalar form parameter passes the request oracle", async (t) => {
  const request = fixture(t);
  assert.equal((await request("/token", { method: "POST", body: "token=yes" })).status, 200);
  assert.deepEqual((await request("/_check")).body, { ok: true, diffs: [] });
});

for (const body of [
  "token=yes&token=no",
  "token=no&token=yes",
  "token=yes&token=yes",
  "token=yes&token=",
  "token=yes&to%6ben=no",
  "token=no",
  "",
]) {
  test(`scalar form mismatch cannot pass: ${body || "missing token"}`, async (t) => {
    const request = fixture(t);
    await request("/token", { method: "POST", body });
    const result = (await request("/_check")).body;
    assert.equal(result.ok, false);
    assert.match(result.diffs.join("\n"), /form token.*want exactly one "yes"/);
  });
}

test("an absent form expectation still rejects present empty values", async (t) => {
  const request = fixture(t, {
    vector: { ...basic, expect_request: { ...basic.expect_request, form: { absent: "" } } },
  });
  await request("/token", { method: "POST", body: "absent=&absent=" });
  assert.match((await request("/_check")).body.diffs.join("\n"), /form absent.*want absent/);
});

for (const [description, fields, location] of [
  ["string status", { http: { "/token": { status: "200" } } }, "http"],
  ["out-of-range status", { http: { "/token": { status: 600 } } }, "http"],
  ["response typo", { http: { "/token": { stats: 200 } } }, "http"],
  ["numeric response header", { http: { "/token": { headers: { "x-test": 1 } } } }, "headers"],
  ["null HTTP map", { http: null }, "http"],
  ["empty HTTP map", { http: {} }, "http"],
  ["empty sequence", { http_sequence: { "/token": [] } }, "http_sequence"],
  ["string call count", { expect_calls: { "/token": "0" } }, "expect_calls"],
  ["negative call count", { expect_calls: { "/token": -1 } }, "expect_calls"],
  ["fractional call count", { expect_calls: { "/token": 0.5 } }, "expect_calls"],
  ["missing method", { expect_request: { path: "/token" } }, "expect_request"],
  ["assertion typo", { expect_request: { path: "/token", method: "POST", forms: {} } }, "expect_request"],
  ["numeric form expectation", { expect_request: { path: "/token", method: "POST", form: { token: 1 } } }, "form"],
  ["reserved response route", { http: { "/_check": {} } }, "http"],
]) {
  test(`malformed ${description} fails before a response or check`, async (t) => {
    const request = fixture(t, { vector: { ...basic, ...fields } });
    for (const suffix of ["/token", "/_check"]) {
      const result = await request(suffix, { method: "POST", body: "token=yes" });
      assert.equal(result.status, 500);
      assert.match(result.body.error, /invalid sample\/CASE-1\/one/);
      assert.ok(result.body.error.includes(location), result.body.error);
    }
  });
}

for (const spec of [
  {},
  { tests: [] },
  { tests: [null] },
  { tests: [{ id: "CASE-1", vectors: {} }] },
  { tests: [{ id: "CASE-1", vectors: [] }] },
]) {
  test(`invalid file envelope fails explicitly: ${JSON.stringify(spec)}`, async (t) => {
    const request = fixture(t, { spec });
    const result = await request("/_check");
    assert.equal(result.status, 500);
    assert.match(result.body.error, /invalid sample.json/);
  });
}

test("an invalid response cannot pass a zero-call check", async (t) => {
  const request = fixture(t, {
    vector: { name: "one", http: { "/token": { status: "200" } }, expect_calls: { "/token": 0 } },
  });
  assert.equal((await request("/_check")).status, 500);
});

test("a valid zero-call vector passes without a request", async (t) => {
  const request = fixture(t, {
    vector: { name: "one", http: { "/token": {} }, expect_calls: { "/token": 0 } },
  });
  assert.deepEqual((await request("/_check")).body, { ok: true, diffs: [] });
});

test("ambiguous static and sequenced responses are rejected", async (t) => {
  const request = fixture(t, { vector: { ...basic, http_sequence: { "/token": [{}] } } });
  const result = await request("/_check");
  assert.equal(result.status, 500);
  assert.match(result.body.error, /paths in both http and http_sequence: \/token/);
});

test("static and sequenced responses can use different paths", async (t) => {
  const request = fixture(t, {
    vector: {
      name: "one",
      http: { "/discovery": { status: 201 } },
      http_sequence: { "/token": [{ status: 401 }, { status: 200 }] },
      expect_calls: { "/discovery": 1, "/token": 2 },
    },
  });
  assert.equal((await request("/discovery")).status, 201);
  assert.equal((await request("/token")).status, 401);
  assert.equal((await request("/token")).status, 200);
  assert.deepEqual((await request("/_check")).body, { ok: true, diffs: [] });
});

for (const [description, spec] of [
  ["case IDs", { tests: [{ id: "CASE-1", vectors: [basic] }, { id: "CASE-1", vectors: [{ ...basic, http: { "/token": { status: 401 } } }] }] }],
  ["vector names", { tests: [{ id: "CASE-1", vectors: [basic, { ...basic, http: { "/token": { status: 401 } } }] }] }],
  ["named and unnamed keys", { tests: [{ id: "CASE-1", vectors: [{ http: basic.http }, { name: "0", http: basic.http }] }] }],
]) {
  test(`ambiguous ${description} fail instead of selecting the first vector`, async (t) => {
    const request = fixture(t, { vector: description === "named and unnamed keys" ? { name: "0" } : basic, spec });
    const result = await request("/token");
    assert.equal(result.status, 500);
    assert.match(result.body.error, /duplicate key/);
  });
}

test("pure-logic vectors may retain descriptive names beside an HTTP vector", async (t) => {
  const request = fixture(t, {
    spec: { tests: [{ id: "CASE-1", vectors: [{ name: "descriptive logic name", input: { operation: "verify" } }, basic] }] },
  });
  await request("/token", { method: "POST", body: "token=yes" });
  assert.deepEqual((await request("/_check")).body, { ok: true, diffs: [] });
});

for (const value of ["\u0001", "\u007f", "\u0100"]) {
  test(`HTTP-invalid header ${JSON.stringify(value)} cannot pass even with zero calls`, async (t) => {
    assert.throws(() => http.validateHeaderValue("x-test", value), { code: "ERR_INVALID_CHAR" });
    const request = fixture(t, {
      vector: {
        name: "one",
        http: { "/token": { headers: { "x-test": value } } },
        expect_calls: { "/token": 0 },
      },
    });
    for (const suffix of ["/_check", "/token", "/_check"]) {
      const result = await request(suffix);
      assert.equal(result.status, 500);
      assert.match(result.body.error, /sample\/CASE-1\/one.*headers/);
    }
  });
}

test("valid horizontal-tab and Latin-1 response headers remain supported", async (t) => {
  const value = "\tvalue \u00ff";
  http.validateHeaderValue("x-test", value);
  const request = fixture(t, { vector: { ...basic, http: { "/token": { headers: { "x-test": value } } } } });
  const result = await request("/token", { method: "POST", body: "token=yes" });
  assert.equal(result.status, 200);
  assert.equal(result.response.get("x-test"), value);
  assert.deepEqual((await request("/_check")).body, { ok: true, diffs: [] });
});

test("all checked-in canned vectors remain valid at the fixture boundary", async () => {
  const specDir = fileURLToPath(new URL("../../spec", import.meta.url));
  const app = new Koa();
  const routes = vectorRoutes({ issuer: "http://fixture", specDir });
  let checked = 0;
  for (const file of fs.readdirSync(path.join(specDir, "vectors"))) {
    if (!file.endsWith(".json")) continue;
    const capability = file.slice(0, -5);
    const spec = JSON.parse(fs.readFileSync(path.join(specDir, "vectors", file)));
    for (const tc of spec.tests) {
      for (const [index, vector] of (tc.vectors ?? []).entries()) {
        if (!Object.hasOwn(vector, "http") && !Object.hasOwn(vector, "http_sequence")) continue;
        const url = `/v/compat/${capability}/${tc.id}/${vector.name ?? index}/_check`;
        const result = await dispatch(app, routes, url);
        assert.equal(result.status, 200, `${url}: ${JSON.stringify(result.body)}`);
        checked++;
      }
    }
  }
  assert.ok(checked > 0, "no checked-in canned vectors were validated");
});
