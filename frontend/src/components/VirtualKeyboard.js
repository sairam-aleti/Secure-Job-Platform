import React, { useState, useEffect } from 'react';

export default function VirtualKeyboard({ onKeyPress, onBackspace, onClear, disabled }) {
  const [keys, setKeys] = useState([]);

  useEffect(() => {
    shuffleKeys();
  }, []);

  const shuffleKeys = () => {
    let numericKeys = Array.from(Array(10).keys());
    for (let i = numericKeys.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [numericKeys[i], numericKeys[j]] = [numericKeys[j], numericKeys[i]];
    }
    setKeys(numericKeys);
  };

  const containerStyle = {
    display: 'grid',
    gridTemplateColumns: 'repeat(3, 1fr)',
    gap: '8px',
    maxWidth: '260px',
    margin: '20px auto',
    padding: '20px',
    background: 'var(--cy-glass-bg, rgba(255,255,255,0.75))',
    backdropFilter: 'blur(24px)',
    WebkitBackdropFilter: 'blur(24px)',
    borderRadius: '16px',
    border: '1px solid rgba(255,255,255,0.8)',
    boxShadow: '0 8px 32px -8px rgba(10,102,194,0.1)',
    position: 'relative',
  };

  const innerBorderStyle = {
    position: 'absolute',
    top: '4px',
    left: '4px',
    right: '4px',
    bottom: '4px',
    border: '1px dashed rgba(10,102,194,0.15)',
    borderRadius: '12px',
    pointerEvents: 'none',
  };

  const keyStyle = {
    padding: '14px',
    fontSize: '18px',
    fontWeight: '700',
    fontFamily: "'Space Grotesk', sans-serif",
    color: 'var(--cy-text-main, #001328)',
    background: 'rgba(255,255,255,0.6)',
    border: '1px dashed rgba(10,102,194,0.15)',
    borderRadius: '8px',
    cursor: 'pointer',
    textAlign: 'center',
    userSelect: 'none',
    transition: 'all 0.2s ease',
    position: 'relative',
    zIndex: 1,
  };

  const actionKeyStyle = {
    ...keyStyle,
    background: 'rgba(10,102,194,0.06)',
    color: 'var(--cy-brand, #0A66C2)',
    fontSize: '14px',
    fontFamily: "'JetBrains Mono', monospace",
    fontWeight: '600',
  };

  const clearKeyStyle = {
    ...actionKeyStyle,
    color: '#dc2626',
    background: 'rgba(220,38,38,0.05)',
    border: '1px dashed rgba(220,38,38,0.2)',
  };

  return (
    <div>
      <div style={{ textAlign: 'center', marginBottom: '8px' }}>
        <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '10px', color: 'var(--cy-brand, #0A66C2)', textTransform: 'uppercase', letterSpacing: '2px' }}>SECURE_INPUT</span>
      </div>
      <div style={{ textAlign: 'center', marginBottom: '10px' }}>
        <button 
          type="button" onClick={shuffleKeys} 
          style={{ background: 'none', border: 'none', color: 'var(--cy-text-mute, #6C7A89)', fontSize: '11px', cursor: 'pointer', fontFamily: "'JetBrains Mono', monospace", letterSpacing: '0.5px' }}
        >
          ↻ Shuffle Keys
        </button>
      </div>
      
      <div style={containerStyle}>
        <div style={innerBorderStyle}></div>
        {keys.slice(0, 9).map((num) => (
          <button 
            key={num} type="button" style={keyStyle} 
            onClick={() => onKeyPress(num.toString())} disabled={disabled}
            onMouseEnter={(e) => { e.target.style.background = 'var(--cy-brand, #0A66C2)'; e.target.style.color = '#fff'; e.target.style.borderColor = 'var(--cy-brand, #0A66C2)'; e.target.style.boxShadow = '0 4px 12px rgba(10,102,194,0.2)'; }}
            onMouseLeave={(e) => { e.target.style.background = 'rgba(255,255,255,0.6)'; e.target.style.color = 'var(--cy-text-main, #001328)'; e.target.style.borderColor = 'rgba(10,102,194,0.15)'; e.target.style.boxShadow = 'none'; }}
          >
            {num}
          </button>
        ))}
        
        <button type="button" style={clearKeyStyle} onClick={onClear} disabled={disabled}>C</button>
        
        <button 
          key={keys[9]} type="button" style={keyStyle} 
          onClick={() => onKeyPress(keys[9]?.toString())} disabled={disabled}
          onMouseEnter={(e) => { e.target.style.background = 'var(--cy-brand, #0A66C2)'; e.target.style.color = '#fff'; e.target.style.borderColor = 'var(--cy-brand, #0A66C2)'; e.target.style.boxShadow = '0 4px 12px rgba(10,102,194,0.2)'; }}
          onMouseLeave={(e) => { e.target.style.background = 'rgba(255,255,255,0.6)'; e.target.style.color = 'var(--cy-text-main, #001328)'; e.target.style.borderColor = 'rgba(10,102,194,0.15)'; e.target.style.boxShadow = 'none'; }}
        >
          {keys[9]}
        </button>
        
        <button type="button" style={actionKeyStyle} onClick={onBackspace} disabled={disabled}>⌫</button>
      </div>
    </div>
  );
}