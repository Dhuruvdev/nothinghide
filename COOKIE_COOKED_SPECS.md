# Cookie Cooked: Protection System

## Deliverables Summary

### 1. Architecture Diagram (Mental Model)
- **Edge Layer**: Browser Extension scans for HttpOnly/Secure/SameSite flags.
- **Middleware**: Intercepts requests, hashes fingerprints, checks IP/ASN reputation.
- **Intelligence Layer**: Behavioral scoring (Sequence, Request Rate).
- **Control Layer**: Revocation (Score >70) or Step-up Auth (Score 30-70).

### 2. Database Schema (PostgreSQL)
```sql
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    hashed_fingerprint TEXT NOT NULL, -- Never store raw fingerprint
    last_ip TEXT NOT NULL,
    last_asn TEXT,
    risk_score INT DEFAULT 0,
    expires_at TIMESTAMP NOT NULL,
    metadata JSONB DEFAULT '{}'
);
```

### 3. Machine Learning Model Choice
- **Model**: **Isolation Forest** (Unsupervised Anomaly Detection).
- **Features**: 
  - `time_delta`: Interval between requests.
  - `geo_velocity`: Speed between sequential IPs.
  - `asn_stability`: Changes in Network provider.
  - `header_consistency`: Variations in User-Agent/Headers.
- **Logic**: Outlier score is normalized to 0-100 scale.

### 4. Code Examples (Node.js)
See `cookie-cooked-core.js` for the middleware implementation.

### 5. UI Design
See `dashboard.jsx` for the "Check" button and risk transparency dashboard.
