const express = require('express');
const crypto = require('crypto');
const app = express();

function base32tohex(base32) {
    const base32chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits = '';
    let hex = '';
    for (let i = 0; i < base32.length; i++) {
        const val = base32chars.indexOf(base32.toUpperCase().charAt(i));
        if (val === -1) continue;
        bits += val.toString(2).padStart(5, '0');
    }
    for (let i = 0; i + 4 <= bits.length; i += 4) {
        hex += parseInt(bits.substr(i, 4), 2).toString(16);
    }
    return hex;
}

app.get('/otp', (req, res) => {
    const secret = req.query.secret;
    if (!secret) return res.status(400).send("Secret missing");

    try {
        const cleanSecret = secret.replace(/\s+/g, '').toUpperCase();
        const key = Buffer.from(base32tohex(cleanSecret), 'hex');
        const time = Math.floor(Math.floor(Date.now() / 1000) / 30);
        const timeBuffer = Buffer.alloc(8);
        let tempTime = time;
        for (let i = 7; i >= 0; i--) {
            timeBuffer[i] = tempTime & 0xff;
            tempTime = tempTime >> 8;
        }
        const hmac = crypto.createHmac('sha1', key).update(timeBuffer).digest();
        const offset = hmac[hmac.length - 1] & 0xf;
        const code = ((hmac[offset] & 0x7f) << 24) |
                     ((hmac[offset + 1] & 0xff) << 16) |
                     ((hmac[offset + 2] & 0xff) << 8) |
                     (hmac[offset + 3] & 0xff);
        const otp = (code % 1000000).toString().padStart(6, '0');
        res.send(otp);
    } catch (err) {
        res.status(500).send("Error generating OTP");
    }
});

// ভেরসেলের জন্য এক্সপোর্ট করা জরুরি
module.exports = app;
