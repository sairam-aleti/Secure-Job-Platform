import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence, useScroll, useTransform } from 'framer-motion';

const OWASP_TOP_10 = [
  "A01:2021-Broken Access Control",
  "A02:2021-Cryptographic Failures",
  "A03:2021-Injection",
  "A04:2021-Insecure Design",
  "A05:2021-Security Misconfiguration",
  "A06:2021-Vulnerable and Outdated Components",
  "A07:2021-Identification and Authentication Failures",
  "A08:2021-Software and Data Integrity Failures",
  "A09:2021-Security Logging and Monitoring Failures",
  "A10:2021-Server-Side Request Forgery (SSRF)"
];

const SecurityBackground = () => {
  const [splashes, setSplashes] = useState([]);
  const [currentIndex, setCurrentIndex] = useState(0);

  // Parallax Scrolling effects for orbs
  const { scrollYProgress } = useScroll();
  const y1 = useTransform(scrollYProgress, [0, 1], [0, -100]);
  const y2 = useTransform(scrollYProgress, [0, 1], [0, -200]);
  const y3 = useTransform(scrollYProgress, [0, 1], [0, -50]);

  const currentIndexRef = useRef(0);

  useEffect(() => {
    const handleGlobalClick = (e) => {
      // Ignore clicks on interactive elements
      const interactiveElements = ['BUTTON', 'A', 'INPUT', 'SELECT', 'TEXTAREA', 'LABEL'];
      if (interactiveElements.includes(e.target.tagName) || e.target.closest('button') || e.target.closest('a')) {
        return;
      }

      // NO RESTRICTION: Trigger on any empty space (per latest request)
      const id = Date.now();
      const currentIndex = currentIndexRef.current;
      const text = OWASP_TOP_10[currentIndex];

      setSplashes(prev => [...prev, { id, x: e.clientX, y: e.clientY, text, index: currentIndex }]);
      currentIndexRef.current = (currentIndex + 1) % OWASP_TOP_10.length;

      // Auto-remove splash after animation (increased to 7s to account for hover/sink)
      setTimeout(() => {
        setSplashes(prev => prev.filter(s => s.id !== id));
      }, 7000);
    };

    window.addEventListener('mousedown', handleGlobalClick);
    return () => window.removeEventListener('mousedown', handleGlobalClick);
  }, []);

  return (
    <>
      {/* Background Layer (Fixed and Behind) */}
      <div 
        className="app-grid-bg" 
        style={{ pointerEvents: 'none', position: 'fixed', inset: 0, overflow: 'hidden', zIndex: -1 }}
      >
        {/* Mesh Gradients */}
        <div className="bg-mesh" />

        {/* Orbs with Parallax */}
        <motion.div className="orb-1" style={{ y: y1 }} />
        <motion.div className="orb-2" style={{ y: y2 }} />
        <motion.div className="orb-3" style={{ y: y3 }} />
      </div>

      {/* Interactive Overlay Layer (Fixed and In-Front) */}
      <div 
        style={{ pointerEvents: 'none', position: 'fixed', inset: 0, overflow: 'hidden', zIndex: 999999 }}
      >
        <AnimatePresence>
          {splashes.map(splash => (
            <div key={splash.id} style={{ position: 'absolute', left: splash.x, top: splash.y, pointerEvents: 'none' }}>
              {/* Ripple Effect */}
              <motion.div 
                className="splash-ripple"
                initial={{ scale: 0, opacity: 1 }}
                animate={{ scale: 4, opacity: 0 }}
                transition={{ duration: 1, ease: "easeOut" }}
              />
              
              {/* OWASP Label "Blooping" out of water */}
              <motion.div
                className="owasp-label"
                initial={{ y: 0, opacity: 0, scale: 0.8 }}
                animate={[
                  { y: -100, opacity: 1, scale: 1 }, // Come out
                  { y: -105, transition: { duration: 2, repeat: Infinity, repeatType: "mirror" } }, // Float
                  { y: 60, opacity: 0, scale: 0.5, transition: { delay: 4.5, duration: 1 } } // Sink back (4.5s delay)
                ]}
              >
                <div className="label-content">
                  <span className="vulnerability-tag">THREAT_IDENTIFIED #{splash.index + 1}</span>
                  <span className="vulnerability-name">{splash.text}</span>
                </div>
              </motion.div>
            </div>
          ))}
        </AnimatePresence>
      </div>
    </>
  );
};

export default SecurityBackground;
