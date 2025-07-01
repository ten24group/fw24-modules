import React from 'react';

const LoadingSpinner: React.FC = () => (
  <div style={{ textAlign: 'center', padding: '1rem' }}>
    <div
      style={{
        width: '2rem',
        height: '2rem',
        border: '4px solid #ccc',
        borderTopColor: '#333',
        borderRadius: '50%',
        animation: 'spin 1s linear infinite',
        margin: '0 auto',
      }}
    />
    <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
  </div>
);

export default LoadingSpinner; 