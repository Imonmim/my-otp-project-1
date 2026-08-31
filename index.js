const express = require('express');
const { TOTP } = require('otplib');
const app = express();

app.get('/otp', (req, res) => {
    const secret = req.query.secret;
    if (!secret) return res.status(400).send("Secret missing");

    try {
        // স্পেস বা অতিরিক্ত ক্যারেক্টার ক্লিন করা
        const cleanSecret = secret.replace(/\s+/g, '').toUpperCase();
        
        // otplib দিয়ে নিখুঁতভাবে আসল টু-এফএ কোড জেনারেট করা
        const token = TOTP.generate(cleanSecret);
        
        res.send(token);
    } catch (err) {
        res.status(500).send("Error generating OTP");
    }
});

module.exports = app;
