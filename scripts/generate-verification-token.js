const crypto = require("crypto");

const expiresAt = process.argv[2];

if (expiresAt && !Number.isFinite(Date.parse(expiresAt))) {
    console.error("Expiration must be a valid ISO-8601 date.");
    process.exit(1);
}

const token = crypto.randomBytes(32).toString("hex");
const hash = crypto.createHash("sha256").update(token).digest("hex");

console.log("Share this token only through a secure channel:");
console.log(token);
console.log("Store only this hash in verification configuration:");
console.log(JSON.stringify({
    hash,
    status: "active",
    ...(expiresAt ? { expiresAt } : {})
}));
