import React, { useState, useEffect } from 'react';

const CookieCookedUI = () => {
    const [data, setData] = useState(null);
    const [loading, setLoading] = useState(false);

    const fetchStatus = async () => {
        setLoading(true);
        try {
            const res = await fetch('/api/cooked/dashboard');
            const json = await res.json();
            setData(json);
        } finally {
            setLoading(false);
        }
    };

    const handleCheck = async () => {
        setLoading(true);
        await fetch('/api/cooked/check', { method: 'POST' });
        await fetchStatus();
        setLoading(false);
    };

    return (
        <div style={{ padding: '20px', fontFamily: 'sans-serif' }}>
            <h1>Cookie Cooked Intelligence</h1>
            
            <button 
                onClick={handleCheck}
                disabled={loading}
                style={{
                    padding: '10px 20px',
                    fontSize: '18px',
                    backgroundColor: '#3498db',
                    color: 'white',
                    border: 'none',
                    borderRadius: '5px',
                    cursor: 'pointer'
                }}
            >
                {loading ? 'Scanning...' : 'Check'}
            </button>

            {data && (
                <div style={{ marginTop: '30px' }}>
                    <h3>Active Sessions</h3>
                    {data.sessions.map(s => (
                        <div key={s.id} style={{ 
                            border: '1px solid #ddd', 
                            padding: '10px', 
                            margin: '10px 0',
                            borderRadius: '8px',
                            backgroundColor: s.is_current ? '#f0f9ff' : 'white'
                        }}>
                            <strong>{s.device}</strong> {s.is_current && '(Current)'}
                            <p>Region: {s.region} | Last Active: {s.last_active}</p>
                            <p>Risk Score: <span style={{ color: s.risk_score > 40 ? 'red' : 'green' }}>{s.risk_score}</span></p>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
};

export default CookieCookedUI;
