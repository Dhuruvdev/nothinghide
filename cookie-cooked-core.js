const crypto = require('crypto');

/**
 * Cookie Cooked Middleware
 * Prevents, detects, and reacts to cookie hijacking.
 */
const cookieCooked = (db) => async (req, res, next) => {
    const sessionId = req.cookies['session_id'];
    const fingerprint = hashFingerprint(req);
    
    if (!sessionId) return next();

    const session = await db.query('SELECT * FROM sessions WHERE id = $1', [sessionId]);
    
    if (!session) {
        res.clearCookie('session_id');
        return res.status(401).send('Invalid Session');
    }

    let riskScore = 0;

    // 1. Check Fingerprint
    if (session.hashed_fingerprint !== fingerprint) {
        riskScore += 40;
    }

    // 2. Check Geo/IP Travel (Mock logic)
    const currentIp = req.ip;
    if (session.last_ip !== currentIp) {
        riskScore += 20; // Basic IP change
    }

    // 3. Response Automation
    if (riskScore >= 70) {
        await db.query('DELETE FROM sessions WHERE id = $1', [sessionId]);
        res.clearCookie('session_id');
        return res.status(403).send('Session revoked due to high risk');
    }

    if (riskScore >= 30) {
        // Trigger Step-up Auth (e.g., re-verify OTP)
        req.needsStepUp = true;
    }

    // Update Session with new metadata
    await db.query('UPDATE sessions SET last_ip = $1, risk_score = $2 WHERE id = $3', [currentIp, riskScore, sessionId]);

    next();
};

function hashFingerprint(req) {
    const data = req.headers['user-agent'] + (req.headers['accept-language'] || '');
    return crypto.createHash('sha256').update(data).digest('hex');
}

module.exports = cookieCooked;
