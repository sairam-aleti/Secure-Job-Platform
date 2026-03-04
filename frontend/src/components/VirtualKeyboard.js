import React, { useState, useEffect } from 'react';

// STYLES FOR THE KEYBOARD
const styles = {
  keyboardContainer: {
    display: 'grid',
    gridTemplateColumns: 'repeat(3, 1fr)',
    gap: '10px',
    maxWidth: '250px',
    margin: '20px auto',
    padding: '15px',
    background: '#f9fafb',
    borderRadius: '12px',
    border: '1px solid #e5e7eb',
    boxShadow: 'inset 0 2px 4px rgba(0,0,0,0.02)'
  },
  key: {
    padding: '15px',
    fontSize: '18px',
    fontWeight: '600',
    color: '#1a1a2e',
    background: '#ffffff',
    border: '1px solid #d1d5db',
    borderRadius: '8px',
    cursor: 'pointer',
    textAlign: 'center',
    userSelect: 'none',
    boxShadow: '0 2px 4px rgba(0,0,0,0.05)',
    transition: 'all 0.1s ease'
  },
  keyAction: {
    background: '#eef2ff',
    color: '#3461c7',
  }
};

export default function VirtualKeyboard({ onKeyPress, onBackspace, onClear, disabled }) {
  const [keys, setKeys] = useState([]);

  // RANDOMIZE KEYS ON LOAD (Defeats mouse-tracking malware)
  useEffect(() => {
    shuffleKeys();
  }, []);

  const shuffleKeys = () => {
    // Array from 0 to 9
    let numericKeys = Array.from(Array(10).keys());
    // Fisher-Yates Shuffle
    for (let i = numericKeys.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [numericKeys[i], numericKeys[j]] = [numericKeys[j], numericKeys[i]];
    }
    setKeys(numericKeys);
  };

  return (
    <div>
      <div style={{ textAlign: 'center', marginBottom: '10px' }}>
        <button 
          type="button" 
          onClick={shuffleKeys} 
          style={{ background: 'none', border: 'none', color: '#6b7280', fontSize: '12px', cursor: 'pointer', textDecoration: 'underline' }}
        >
          Shuffle Keys
        </button>
      </div>
      
      <div style={styles.keyboardContainer}>
        {/* Render the first 9 shuffled keys */}
        {keys.slice(0, 9).map((num) => (
          <button 
            key={num} 
            type="button" 
            style={styles.key} 
            onClick={() => onKeyPress(num.toString())}
            disabled={disabled}
          >
            {num}
          </button>
        ))}
        
        {/* Bottom Row: Clear, the last number, Backspace */}
        <button 
          type="button" 
          style={{...styles.key, ...styles.keyAction, color: '#dc2626'}} 
          onClick={onClear}
          disabled={disabled}
        >
          C
        </button>
        
        <button 
          key={keys[9]} 
          type="button" 
          style={styles.key} 
          onClick={() => onKeyPress(keys[9].toString())}
          disabled={disabled}
        >
          {keys[9]}
        </button>
        
        <button 
          type="button" 
          style={{...styles.key, ...styles.keyAction}} 
          onClick={onBackspace}
          disabled={disabled}
        >
          ⌫
        </button>
      </div>
    </div>
  );
}