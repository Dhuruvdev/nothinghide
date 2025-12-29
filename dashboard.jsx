import React, { useState } from 'react';

export default function CookieCookedDashboard() {
  const [risk, setRisk] = useState(12);

  const handleCheck = async () => {
    // Trigger real-time scan
    const res = await fetch('/api/session/check');
    const data = await res.json();
    setRisk(data.score);
  };

  return (
    <div className="p-6 max-w-md mx-auto bg-white rounded-xl shadow-md space-y-4">
      <h1 className="text-xl font-bold">Cookie Cooked Dashboard</h1>
      <div className="flex justify-between items-center">
        <span>Current Risk Level:</span>
        <span className={`font-bold ${risk > 50 ? 'text-red-500' : 'text-green-500'}`}>
          {risk}/100
        </span>
      </div>
      
      <button 
        onClick={handleCheck}
        className="w-full py-2 px-4 bg-blue-600 text-white font-semibold rounded-lg shadow-md hover:bg-blue-700 focus:outline-none"
      >
        Check
      </button>

      <div className="mt-4 text-sm text-gray-500">
        <p>Last scanned: {new Date().toLocaleTimeString()}</p>
        <p>Active Devices: 1 (Verified)</p>
      </div>
    </div>
  );
}
