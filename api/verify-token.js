const crypto = require("crypto");

const rateWindows = new Map();

function json(response, status, body) {
    response.status(status);
    response.setHeader("Content-Type", "application/json; charset=utf-8");
    response.setHeader("Cache-Control", "no-store");
    response.setHeader("Content-Security-Policy", "default-src 'none'");
    response.setHeader("X-Content-Type-Options", "nosniff");
    response.end(JSON.stringify(body));
}

function secureEqual(left, right) {
    if (!left || !right || left.length !== right.length) {
        return false;
    }

    return crypto.timingSafeEqual(Buffer.from(left), Buffer.from(right));
}

function isRateLimited(request) {
    const forwarded = request.headers["x-forwarded-for"];
    const address = typeof forwarded === "string"
        ? forwarded.split(",")[0].trim()
        : (request.socket && request.socket.remoteAddress) || "unknown";
    const key = crypto.createHash("sha256").update(address).digest("hex");
    const now = Date.now();
    const window = rateWindows.get(key);

    if (!window || now >= window.resetAt) {
        rateWindows.set(key, { count: 1, resetAt: now + 60_000 });
        return false;
    }

    window.count += 1;
    return window.count > 30;
}

async function readKvRecord(hash) {
    const url = process.env.VERCEL_KV_REST_API_URL || process.env.KV_REST_API_URL;
    const token = process.env.VERCEL_KV_REST_API_TOKEN || process.env.KV_REST_API_TOKEN;
    if (!url || !token) {
        return null;
    }

    try {
        const response = await fetch(`${url.replace(/\/$/, "")}/get/verification-token:${hash}`, {
            headers: {
                Authorization: `Bearer ${token}`,
                Accept: "application/json"
            },
            cache: "no-store"
        });

        if (!response.ok) {
            return null;
        }

        const payload = await response.json();
        if (!payload.result) {
            return null;
        }

        return typeof payload.result === "string"
            ? JSON.parse(payload.result)
            : payload.result;
    } catch {
        return null;
    }
}

async function consumeKvOneTime(hash, ttlSeconds) {
    const url = process.env.VERCEL_KV_REST_API_URL || process.env.KV_REST_API_URL;
    const token = process.env.VERCEL_KV_REST_API_TOKEN || process.env.KV_REST_API_TOKEN;
    if (!url || !token) {
        return null;
    }

    try {
        const response = await fetch(
            `${url.replace(/\/$/, "")}/set/verification-used:${hash}/1/NX/EX/${ttlSeconds}`,
            {
                method: "POST",
                headers: {
                    Authorization: `Bearer ${token}`,
                    Accept: "application/json"
                },
                cache: "no-store"
            }
        );

        if (!response.ok) {
            return null;
        }

        const payload = await response.json();
        return payload.result === "OK";
    } catch {
        return null;
    }
}

function readEnvironmentRecord(hash) {
    if (!process.env.VERIFICATION_TOKENS) {
        return null;
    }

    try {
        const tokens = JSON.parse(process.env.VERIFICATION_TOKENS);
        if (Array.isArray(tokens)) {
            return tokens.find((record) => (
                typeof record.hash === "string"
                && record.hash.toLowerCase() === hash
            )) || null;
        }

        return tokens[hash] || null;
    } catch {
        return null;
    }
}

module.exports = async function handler(request, response) {
    if (request.method !== "GET") {
        response.setHeader("Allow", "GET");
        json(response, 405, { valid: false });
        return;
    }

    if (isRateLimited(request)) {
        json(response, 429, { valid: false });
        return;
    }

    const token = Array.isArray(request.query.t) ? request.query.t[0] : request.query.t;
    if (typeof token !== "string" || !/^[a-fA-F0-9]{64}$/.test(token)) {
        json(response, 400, { valid: false });
        return;
    }

    const suppliedHash = crypto.createHash("sha256").update(token).digest("hex");
    const record = await readKvRecord(suppliedHash) || readEnvironmentRecord(suppliedHash);
    if (!record) {
        json(response, 404, { valid: false });
        return;
    }

    const configuredHash = typeof record.hash === "string"
        ? record.hash.toLowerCase()
        : null;

    if (configuredHash && !secureEqual(suppliedHash, configuredHash)) {
        json(response, 404, { valid: false });
        return;
    }

    if (record.status && String(record.status).toLowerCase() !== "active") {
        json(response, 404, { valid: false });
        return;
    }

    let ttlSeconds = 86400;
    if (record.expiresAt) {
        const expiresAt = Date.parse(record.expiresAt);
        if (!Number.isFinite(expiresAt) || Date.now() >= expiresAt) {
            json(response, 410, { valid: false });
            return;
        }
        ttlSeconds = Math.max(1, Math.ceil((expiresAt - Date.now()) / 1000));
    }

    if (record.oneTime === true) {
        const consumed = await consumeKvOneTime(suppliedHash, ttlSeconds);
        if (consumed === false) {
            json(response, 410, { valid: false });
            return;
        }
    }

    json(response, 200, { valid: true });
};
