// One-time migration: moves vault entries saved by the old version of SecureKeep
// (server-side CryptoJS encryption, no user accounts) into a new account's
// zero-knowledge vault.
//
// Usage:   node migrate-legacy.js            (prompts for everything)
//          node migrate-legacy.js --delete-old   (also removes the old entries after success)
//
// You need:
//   - the username and master password of the vault you created in the new app
//   - your OLD master password
//   - the OLD salt: open the app in the browser you used before, press F12,
//     and run  localStorage.getItem("salt")  in the Console

require("dotenv").config();
const crypto = require("crypto");
const path = require("path");
const readline = require("readline");
const { pathToFileURL } = require("url");
const { MongoClient } = require("mongodb");

const ask = (question, hidden = false) =>
    new Promise((resolve) => {
        const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
        if (hidden) {
            rl._writeToOutput = (s) => {
                if (s.startsWith(question)) rl.output.write(question);
            };
        }
        rl.question(question, (answer) => {
            rl.close();
            if (hidden) process.stdout.write("\n");
            resolve(answer);
        });
    });

const input = async (envName, question, hidden) => process.env[envName] ?? ask(question, hidden);

// Old key: CryptoJS.PBKDF2(password, saltString, SHA-256, 10000 iterations, 256 bits).toString()
const oldClientKey = (oldPassword, oldSalt) =>
    crypto.pbkdf2Sync(oldPassword, Buffer.from(oldSalt, "utf8"), 10000, 32, "sha256").toString("hex");

// Decrypts CryptoJS.AES.encrypt(text, passphrase) output (OpenSSL "Salted__" format).
const decryptCryptoJS = (ciphertextB64, passphrase) => {
    const raw = Buffer.from(ciphertextB64, "base64");
    if (raw.subarray(0, 8).toString("latin1") !== "Salted__") throw new Error("Not CryptoJS format");
    const salt = raw.subarray(8, 16);
    const pass = Buffer.from(passphrase, "utf8");
    let derived = Buffer.alloc(0);
    let block = Buffer.alloc(0);
    while (derived.length < 48) {
        block = crypto.createHash("md5").update(Buffer.concat([block, pass, salt])).digest();
        derived = Buffer.concat([derived, block]);
    }
    const decipher = crypto.createDecipheriv("aes-256-cbc", derived.subarray(0, 32), derived.subarray(32, 48));
    const text = Buffer.concat([decipher.update(raw.subarray(16)), decipher.final()]).toString("utf8");
    if (!text) throw new Error("Empty result");
    return text;
};

const main = async () => {
    const deleteOld = process.argv.includes("--delete-old");
    const vc = await import(pathToFileURL(path.join(__dirname, "../client/src/vaultCrypto.js")).href);

    const client = new MongoClient(process.env.MONGODB_URI);
    await client.connect();
    const db = client.db("secureKeep");
    const users = db.collection("users");
    const passwords = db.collection("passwords");

    try {
        if (deleteOld) {
            const { deletedCount } = await passwords.deleteMany({ legacyMigratedTo: { $exists: true } });
            if (deletedCount) console.log(`Deleted ${deletedCount} old entries that were already migrated.`);
        }

        const legacy = await passwords
            .find({ iv: { $exists: false }, legacyMigratedTo: { $exists: false } })
            .toArray();
        if (legacy.length === 0) {
            console.log("No old-format entries left to migrate.");
            return;
        }
        console.log(`Found ${legacy.length} old-format entries.\n`);

        // New account: verify the master password before encrypting anything with it
        const username = (await input("MIGRATE_USERNAME", "New vault username: ")).trim().toLowerCase();
        const user = await users.findOne({ username });
        if (!user) throw new Error(`No account named "${username}". Create the vault in the app first.`);
        const newPassword = await input("MIGRATE_NEW_PASSWORD", "New vault master password: ", true);
        const { encKey, authKey } = await vc.deriveKeys(newPassword, user.kdfSalt, user.kdfIterations);
        const authHash = crypto.scryptSync(authKey, user.authSalt, 64);
        if (!crypto.timingSafeEqual(authHash, Buffer.from(user.authHash, "hex"))) {
            throw new Error("New master password is incorrect.");
        }

        // Old vault: verify by decrypting the first entry
        const oldPassword = await input("MIGRATE_OLD_PASSWORD", "OLD master password: ", true);
        const oldSalt = (await input("MIGRATE_OLD_SALT", 'OLD salt (from localStorage.getItem("salt")): ')).trim().replace(/^"|"$/g, "");
        const oldKey = oldClientKey(oldPassword, oldSalt);
        try {
            decryptCryptoJS(legacy[0].password, oldKey);
        } catch {
            throw new Error("Old master password or old salt is incorrect (could not decrypt the first entry). Nothing was changed.");
        }

        let migrated = 0;
        const failed = [];
        for (const entry of legacy) {
            try {
                const password = decryptCryptoJS(entry.password, oldKey);
                const encrypted = await vc.encryptEntry(encKey, { site: entry.site, username: entry.username, password });
                const now = new Date();
                await passwords.insertOne({
                    userId: user._id,
                    iv: encrypted.iv,
                    data: encrypted.data,
                    createdAt: entry.createdAt ? new Date(entry.createdAt) : now,
                    updatedAt: now,
                });
                if (deleteOld) {
                    await passwords.deleteOne({ _id: entry._id });
                } else {
                    await passwords.updateOne({ _id: entry._id }, { $set: { legacyMigratedTo: user._id } });
                }
                migrated++;
            } catch {
                failed.push(entry.site);
            }
        }

        console.log(`\nMigrated ${migrated} of ${legacy.length} entries into "${username}".`);
        if (failed.length) {
            console.log(`Could not decrypt ${failed.length} (left untouched): ${failed.join(", ")}`);
        }
        if (!deleteOld && migrated) {
            console.log("Old copies were kept (marked as migrated). Re-run with --delete-old later to remove them,");
            console.log("since their site and username fields are stored in plain text.");
        }
    } finally {
        await client.close();
    }
};

main().catch((error) => {
    console.error("\nMigration failed:", error.message);
    process.exit(1);
});
