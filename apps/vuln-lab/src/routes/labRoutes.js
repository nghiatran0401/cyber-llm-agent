const express = require("express");
const path = require("path");

const { categoryForScenario } = require("../scenarios");

const comments = [];
const users = [
  { id: "1001", username: "alice", role: "user", balance: 1400 },
  { id: "1002", username: "bob", role: "admin", balance: 9500 },
];
const products = [
  { id: "p-100", name: "Aero Linen Shirt", category: "Shirts", price: 59, badge: "New" },
  { id: "p-101", name: "Ridge Utility Jacket", category: "Outerwear", price: 129, badge: "Best Seller" },
  { id: "p-102", name: "Harbor Relaxed Denim", category: "Pants", price: 89, badge: "Premium" },
  { id: "p-103", name: "Cloud Knit Hoodie", category: "Sweats", price: 79, badge: "Limited" },
  { id: "p-104", name: "Metro Tailored Blazer", category: "Outerwear", price: 149, badge: "Editor Pick" },
  { id: "p-105", name: "Summit Cotton Tee", category: "Basics", price: 35, badge: "Popular" },
];
const featurePost = {
  id: "post-1",
  title: "How to Build a Capsule Wardrobe for Work and Travel",
  author: "Mina Tran",
  createdAt: "2026-01-12",
  content:
    "A small collection of versatile pieces can cover office, weekends, and travel. Focus on neutral layers, durable fabrics, and two accent colors.",
};

function nowIso() {
  return new Date().toISOString();
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"'`]/g, (char) => {
    const map = {
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
      "`": "&#96;",
    };
    return map[char];
  });
}

function createTelemetryEvent(req, details, config) {
  const category = categoryForScenario(details.scenarioId);
  return {
    timestamp: nowIso(),
    ip: req.ip || req.socket.remoteAddress || "127.0.0.1",
    method: req.method,
    path: req.originalUrl,
    status: Number(details.status || 200),
    userAgent: req.headers["user-agent"] || "",
    scenarioId: details.scenarioId,
    riskHint: details.riskHint,
    payloadSnippet: String(details.payloadSnippet || "").slice(0, 240),
    owaspCategory: category.owasp,
    mitreTechniques: category.mitre,
    message: details.message,
    labMode: config.labMode,
  };
}

function makeLabRouter({ config, telemetry, ctiBridge }) {
  const router = express.Router();

  function emit(req, details) {
    const event = createTelemetryEvent(req, details, config);
    req.securityContext = {
      attackDetected: true,
      scenarioId: event.scenarioId,
      riskHint: event.riskHint,
      payloadSnippet: event.payloadSnippet,
      message: event.message,
      owaspCategory: event.owaspCategory,
    };
    telemetry.recordEvent(event);
    ctiBridge.enqueueEvent(event);
  }

  router.get("/health", (req, res) => {
    res.json({
      ok: true,
      app: config.appName,
      mode: config.labMode,
      ctiApiBase: config.ctiApiBase,
      now: nowIso(),
    });
  });

  function handleLogin(req, res, responseType = "html") {
    const username = String(req.body.username || "");
    const password = String(req.body.password || "");
    const suspicious = /('|--|;|\/\*|\*\/| or )/i.test(username) || /('|--|;| or )/i.test(password);

    if (config.labMode === "vulnerable" && suspicious) {
      emit(req, {
        scenarioId: "sqliLogin",
        riskHint: "SQLi",
        payloadSnippet: `${username}:${password}`,
        status: 200,
        message: "SQLi-like pattern detected in login fields. Auth bypass happened in vulnerable mode.",
      });
      if (responseType === "json") {
        return res.status(200).json({
          ok: true,
          username: "admin",
          role: "admin",
          welcome: "Welcome back to Northwind Apparel.",
        });
      }
      return res
        .status(200)
        .send("<h2>Welcome admin (vulnerable auth bypass)</h2><a href='/'>Back</a>");
    }

    if (username === "admin" && password === "password123") {
      emit(req, {
        scenarioId: "weakSession",
        riskHint: "WeakAuth",
        payloadSnippet: `${username}:${password}`,
        status: 200,
        message: "Login succeeded with weak demo credentials.",
      });
      if (responseType === "json") {
        return res.status(200).json({
          ok: true,
          username: "admin",
          role: "admin",
          welcome: "Welcome back to Northwind Apparel.",
        });
      }
      return res.status(200).send("<h2>Welcome admin</h2><a href='/'>Back</a>");
    }

    emit(req, {
      scenarioId: "bruteForceLogin",
      riskHint: "BruteForce",
      payloadSnippet: `${username}:${password}`,
      status: 401,
      message: "Failed login attempt. Potential brute-force behavior if repeated.",
    });
    if (responseType === "json") {
      return res.status(401).json({ ok: false, error: "Invalid email or password." });
    }
    return res.status(401).send("<h2>Invalid credentials</h2><a href='/'>Back</a>");
  }

  router.post("/login", (req, res) => handleLogin(req, res, "html"));
  router.post("/auth/login", (req, res) => handleLogin(req, res, "json"));

  router.get("/search", (req, res) => {
    const query = String(req.query.q || "");
    const suspicious = /<script|onerror|onload|javascript:/i.test(query);
    if (suspicious) {
      emit(req, {
        scenarioId: "reflectedXss",
        riskHint: "XSS",
        payloadSnippet: query,
        status: 200,
        message: "Reflected XSS payload pattern observed.",
      });
    }
    const rendered =
      config.labMode === "vulnerable"
        ? query
        : query.replace(/[<>"'`]/g, "");
    res.status(200).send(`<h2>Search result for: ${rendered}</h2><a href='/'>Back</a>`);
  });

  function addComment(req, message) {
    const safeMessage = String(message || "");
    comments.unshift({
      id: `${Date.now()}`,
      message: safeMessage,
      createdAt: nowIso(),
    });
    if (/<script|onerror|onload|javascript:/i.test(safeMessage)) {
      emit(req, {
        scenarioId: "storedXssComment",
        riskHint: "StoredXSS",
        payloadSnippet: safeMessage,
        status: 201,
        message: "Stored XSS marker detected in comment.",
      });
    }
  }

  function renderCommentListHtml() {
    const renderedComments = comments
      .slice(0, 10)
      .map((entry) =>
        `<li>${
          config.labMode === "vulnerable" ? entry.message : entry.message.replace(/[<>"'`]/g, "")
        }</li>`
      )
      .join("");
    return `<h2>Comments</h2><ul>${renderedComments}</ul><a href='/'>Back</a>`;
  }

  function commentView(entry) {
    return {
      id: entry.id,
      createdAt: entry.createdAt,
      message: config.labMode === "vulnerable" ? entry.message : escapeHtml(entry.message),
    };
  }

  router.post("/comment", (req, res) => {
    addComment(req, req.body.message);
    res.status(201).send(
      renderCommentListHtml()
    );
  });

  router.get("/api/products", (req, res) => {
    const query = String(req.query.q || "");
    const suspicious = /<script|onerror|onload|javascript:/i.test(query);
    if (suspicious) {
      emit(req, {
        scenarioId: "reflectedXss",
        riskHint: "XSS",
        payloadSnippet: query,
        status: 200,
        message: "Reflected XSS payload pattern observed in storefront search.",
      });
    }
    const normalized = query.trim().toLowerCase();
    const filtered = normalized
      ? products.filter((product) => {
          const haystack =
            `${product.name} ${product.category} ${product.badge}`.toLowerCase();
          return haystack.includes(normalized);
        })
      : products;

    const searchSummary =
      config.labMode === "vulnerable"
        ? `Showing results for "${query}"`
        : `Showing results for "${escapeHtml(query)}"`;

    return res.status(200).json({
      products: filtered,
      searchSummary: query ? searchSummary : "Trending picks this week",
    });
  });

  router.get("/api/blog-post", (_, res) => {
    return res.status(200).json(featurePost);
  });

  router.get("/api/comments", (_, res) => {
    return res.status(200).json({ comments: comments.slice(0, 20).map(commentView) });
  });

  router.post("/api/comments", (req, res) => {
    const message = String(req.body.message || "");
    addComment(req, message);
    return res.status(201).json({
      ok: true,
      comments: comments.slice(0, 20).map(commentView),
    });
  });

  router.get("/admin", (req, res) => {
    const role = String(req.query.role || "guest");
    const debug = String(req.query.debug || "false") === "true";

    if (config.labMode === "vulnerable" && debug) {
      emit(req, {
        scenarioId: "adminBypass",
        riskHint: "AccessControlBypass",
        payloadSnippet: `role=${role}&debug=${debug}`,
        status: 200,
        message: "Broken access control: debug flag bypassed role check.",
      });
      return res
        .status(200)
        .send("<h2>Admin panel (bypassed)</h2><p>Sensitive config leaked.</p><a href='/'>Back</a>");
    }

    if (role !== "admin") {
      emit(req, {
        scenarioId: "adminBypass",
        riskHint: "AccessControlDenied",
        payloadSnippet: `role=${role}`,
        status: 403,
        message: "Blocked unauthorized admin access attempt.",
      });
      return res.status(403).send("<h2>Forbidden</h2><a href='/'>Back</a>");
    }
    return res.status(200).send("<h2>Admin panel</h2><a href='/'>Back</a>");
  });

  router.get("/api/profile/:id", (req, res) => {
    const targetId = String(req.params.id);
    const viewerId = String(req.query.viewer || "");
    const target = users.find((user) => user.id === targetId);
    if (!target) {
      return res.status(404).json({ error: "User not found" });
    }
    if (config.labMode === "vulnerable" || viewerId === targetId) {
      if (viewerId && viewerId !== targetId) {
        emit(req, {
          scenarioId: "idorProfile",
          riskHint: "IDOR",
          payloadSnippet: `viewer=${viewerId}&target=${targetId}`,
          status: 200,
          message: "IDOR pattern: cross-user profile access granted.",
        });
      }
      return res.status(200).json(target);
    }
    emit(req, {
      scenarioId: "idorProfile",
      riskHint: "IDORBlocked",
      payloadSnippet: `viewer=${viewerId}&target=${targetId}`,
      status: 403,
      message: "IDOR attempt blocked in hardened mode.",
    });
    return res.status(403).json({ error: "Forbidden" });
  });

  router.get("/download", (req, res) => {
    const file = String(req.query.file || "readme.txt");
    const suspicious = file.includes("..") || file.startsWith("/");
    if (suspicious) {
      emit(req, {
        scenarioId: "pathTraversalDownload",
        riskHint: "PathTraversal",
        payloadSnippet: file,
        status: config.labMode === "vulnerable" ? 200 : 400,
        message: "Path traversal payload detected in download parameter.",
      });
    }
    if (config.labMode !== "vulnerable" && suspicious) {
      return res.status(400).send("<h2>Invalid file path</h2><a href='/'>Back</a>");
    }
    return res.status(200).send(
      `<h2>Downloading: ${file}</h2><p>Simulated response only.</p><a href='/'>Back</a>`
    );
  });

  router.get("/debug/config", (req, res) => {
    emit(req, {
      scenarioId: "debugConfigLeak",
      riskHint: "Misconfiguration",
      payloadSnippet: "debug=true",
      status: config.labMode === "vulnerable" ? 200 : 404,
      message: "Debug endpoint exposure checked.",
    });
    if (config.labMode === "vulnerable") {
      return res.status(200).json({
        appName: config.appName,
        mode: config.labMode,
        ctiApiBase: config.ctiApiBase,
        sampleToken: "dev-token-12345",
      });
    }
    return res.status(404).json({ error: "Not found" });
  });

  router.post("/import-config", (req, res) => {
    const raw = String(req.body.payload || "");
    let parsed = {};
    try {
      parsed = JSON.parse(raw || "{}");
    } catch (error) {
      return res.status(400).json({ error: "Invalid JSON payload." });
    }

    emit(req, {
      scenarioId: "unsafeDeserializer",
      riskHint: "UnsafeDeserialization",
      payloadSnippet: raw,
      status: 200,
      message: "Config import executed with unsafe object merge semantics.",
    });

    if (config.labMode === "vulnerable") {
      const target = {};
      Object.assign(target, parsed);
      return res.status(200).json({ ok: true, imported: target });
    }

    const clean = {};
    for (const [key, value] of Object.entries(parsed)) {
      if (key === "__proto__" || key === "constructor" || key === "prototype") {
        continue;
      }
      clean[key] = value;
    }
    return res.status(200).json({ ok: true, imported: clean });
  });

  router.get("/component/version", (req, res) => {
    emit(req, {
      scenarioId: "outdatedComponentBanner",
      riskHint: "OutdatedComponent",
      payloadSnippet: "jquery=1.12.4",
      status: 200,
      message: "Outdated frontend dependency banner exposed.",
    });
    return res.status(200).json({
      frontend: "jquery-1.12.4",
      backend: "express-4.x",
      warning: "Simulated outdated component inventory for training.",
    });
  });

  router.get("/token", (req, res) => {
    const weakToken = Buffer.from(`user:${Date.now()}`).toString("base64");
    emit(req, {
      scenarioId: "weakCryptoToken",
      riskHint: "WeakCrypto",
      payloadSnippet: weakToken,
      status: 200,
      message: "Weakly generated token issued.",
    });
    return res.status(200).json({ token: weakToken, note: "This token is intentionally weak." });
  });

  router.get("/static/:file", (req, res) => {
    const requested = String(req.params.file || "");
    const safePath = path.basename(requested);
    res.sendFile(path.join(__dirname, "..", "..", "public", safePath));
  });

  return router;
}

module.exports = {
  makeLabRouter,
};
