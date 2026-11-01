// All vault cryptography runs in the browser via the Web Crypto API.
// The master password and the encryption key never leave this device.

export const KDF_ITERATIONS = 600000; // OWASP 2023 recommendation for PBKDF2-SHA256

const enc = new TextEncoder();
const dec = new TextDecoder();

const toHex = (buf) =>
    Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, "0")).join("");

const fromHex = (hex) => new Uint8Array(hex.match(/.{2}/g).map((h) => parseInt(h, 16)));

const toBase64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));

const fromBase64 = (b64) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));

export const randomSalt = () => toHex(crypto.getRandomValues(new Uint8Array(16)));

// PBKDF2-SHA256 -> 512 bits. The first half becomes the AES-GCM encryption key
// (kept in memory only); the second half is the auth key sent to the server
// for login. Knowing the auth key reveals nothing about the encryption key.
export const deriveKeys = async (masterPassword, saltHex, iterations = KDF_ITERATIONS) => {
    const baseKey = await crypto.subtle.importKey(
        "raw",
        enc.encode(masterPassword),
        "PBKDF2",
        false,
        ["deriveBits"]
    );
    const bits = new Uint8Array(
        await crypto.subtle.deriveBits(
            { name: "PBKDF2", hash: "SHA-256", salt: fromHex(saltHex), iterations },
            baseKey,
            512
        )
    );
    const encKey = await crypto.subtle.importKey(
        "raw",
        bits.slice(0, 32),
        { name: "AES-GCM" },
        false,
        ["encrypt", "decrypt"]
    );
    return { encKey, authKey: toHex(bits.slice(32)) };
};

export const encryptEntry = async (encKey, entry) => {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        encKey,
        enc.encode(JSON.stringify(entry))
    );
    return { iv: toBase64(iv), data: toBase64(ciphertext) };
};

export const decryptEntry = async (encKey, { iv, data }) => {
    const plaintext = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: fromBase64(iv) },
        encKey,
        fromBase64(data)
    );
    return JSON.parse(dec.decode(plaintext));
};
