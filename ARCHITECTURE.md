# Cookie Cooked: Protection System Architecture

## 1. Risk-Based Anomaly Detection logic
- **Impossible Travel**: Calculate velocity between last known IP and current IP.
- **Fingerprinting**: Hash (User-Agent + Screen Res + Timezone + Plugins).
- **ASN Reputation**: Check against known malicious hosting/VPN ranges.

## 2. Zero-Trust Session Lifecycle
- **HttpOnly & Secure**: Mandatory flags.
- **Rotation**: Change session ID on every sensitive action or risk score bump > 20.

## 3. Database Schema (PostgreSQL)
```sql
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    hashed_fingerprint TEXT NOT NULL,
    last_ip TEXT NOT NULL,
    last_asn TEXT,
    last_lat FLOAT,
    last_lon FLOAT,
    risk_score INT DEFAULT 0,
    expires_at TIMESTAMP NOT NULL,
    metadata JSONB DEFAULT '{}'
);

CREATE TABLE risk_logs (
    id SERIAL PRIMARY KEY,
    session_id UUID REFERENCES sessions(id),
    reason TEXT,
    score_delta INT,
    created_at TIMESTAMP DEFAULT NOW()
);
```

## 4. Machine Learning Logic
- **Isolation Forest** or simple **Weighted Scoring**:
  - New ASN: +30
  - Velocity > 800km/h: +50
  - Fingerprint mismatch: +40
  - Score > 70 => AUTO_REVOKE
