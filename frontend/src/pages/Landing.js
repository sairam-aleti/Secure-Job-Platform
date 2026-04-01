import React, { useRef, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { motion, useScroll, useTransform, useSpring, useMotionValue } from 'framer-motion';
import './Landing.css';

// ======================================================================
// REUSABLE COMPONENTS
// ======================================================================
const HUDFrame = ({ children, labelTopL, labelBotR }) => (
  <div style={{ position: 'relative', height: '100%', width: '100%' }}>
    <div className="cy-crosshair cross-tl cross-h"></div>
    <div className="cy-crosshair cross-tr cross-h"></div>
    <div className="cy-crosshair cross-bl cross-h"></div>
    <div className="cy-crosshair cross-br cross-h"></div>
    {labelTopL && <div className="cy-tech-label ctl-top-left">{labelTopL}</div>}
    {labelBotR && <div className="cy-tech-label ctl-bot-left" style={{ right: 0, left: 'auto', textAlign: 'right' }}>{labelBotR}</div>}
    {children}
  </div>
);

const StaggeredText = ({ text }) => {
  const words = text.split(" ");
  return (
    <motion.div initial="hidden" whileInView="visible" viewport={{ once: true }} variants={{ hidden: { opacity: 0 }, visible: { opacity: 1, transition: { staggerChildren: 0.08 } } }} style={{ display: "inline" }}>
      {words.map((word, i) => (
        <motion.span key={i} variants={{ hidden: { opacity: 0, y: 10 }, visible: { opacity: 1, y: 0 } }} style={{ display: "inline-block", marginRight: "8px" }}>{word}</motion.span>
      ))}
    </motion.div>
  );
};

// ======================================================================
// HERO BOUNCING PROFILE CARDS 
// ======================================================================
const JobSeekerCard = () => {
  const [score] = useState(85);
  const [strength] = useState(72);
  return (
    <motion.div
      className="cy-bouncing-card"
      style={{ top: '20px', right: '0px' }}
      animate={{ y: [0, -18, 0] }}
      transition={{ duration: 4, repeat: Infinity, ease: "easeInOut" }}
    >
      {/* Spinning dashed circle */}
      <motion.div className="cy-card-spinning-graphic" animate={{ rotate: 360 }} transition={{ duration: 20, repeat: Infinity, ease: "linear" }} />

      <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
        <div className="cy-card-avatar">LS</div>
        <div>
          <div style={{ fontWeight: 700, fontSize: '18px' }}>Lokesh Singh</div>
          <div style={{ fontSize: '13px', color: 'var(--cy-text-mute)' }}>Senior Engineer · FortKnox Verified ✓</div>
        </div>
      </div>

      <div className="cy-card-badge">✓ Offer Received — Stripe</div>

      <div className="cy-progress-container">
        <div className="cy-progress-header"><span>Application Score</span><span>{score}%</span></div>
        <div className="cy-progress-track">
          <motion.div className="cy-progress-fill" initial={{ width: 0 }} animate={{ width: `${score}%` }} transition={{ duration: 1.5, delay: 0.5 }} />
        </div>
      </div>

      <div className="cy-progress-container">
        <div className="cy-progress-header"><span>Profile Strength</span><span>{strength}%</span></div>
        <div className="cy-progress-track">
          <motion.div className="cy-progress-fill green" initial={{ width: 0 }} animate={{ width: `${strength}%` }} transition={{ duration: 1.5, delay: 0.8 }} />
        </div>
      </div>

      <div className="cy-stat-chips">
        <div className="cy-stat-chip"><div className="cy-stat-chip-num">24</div><div className="cy-stat-chip-label">Applied</div></div>
        <div className="cy-stat-chip"><div className="cy-stat-chip-num">8</div><div className="cy-stat-chip-label">Interviews</div></div>
        <div className="cy-stat-chip"><div className="cy-stat-chip-num">3</div><div className="cy-stat-chip-label">Offers</div></div>
      </div>
    </motion.div>
  );
};

const RecruiterCard = () => {
  const [filled, setFilled] = useState(0);
  useEffect(() => {
    const t = setInterval(() => setFilled(p => p >= 9 ? 0 : p + 1), 1800);
    return () => clearInterval(t);
  }, []);

  return (
    <motion.div
      className="cy-bouncing-card"
      style={{ top: '280px', left: '0px', width: '380px' }}
      animate={{ y: [0, -14, 0] }}
      transition={{ duration: 5, repeat: Infinity, ease: "easeInOut", delay: 1.5 }}
    >
      <motion.div className="cy-card-spinning-graphic" style={{ top: 'auto', bottom: '-40px', right: '-40px' }} animate={{ rotate: -360 }} transition={{ duration: 25, repeat: Infinity, ease: "linear" }} />

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div className="cy-card-avatar" style={{ background: 'var(--cy-brand)', width: '48px', height: '48px', fontSize: '18px' }}>AB</div>
          <div>
            <div style={{ fontWeight: 700, fontSize: '16px' }}>Arun Balaji</div>
            <div style={{ fontSize: '12px', color: 'var(--cy-text-mute)' }}>Head of Talent · FCS Corp</div>
          </div>
        </div>
        <div style={{ fontSize: '11px', fontWeight: 700, color: '#fff', background: '#137333', padding: '4px 10px', borderRadius: '99px' }}>HIRING</div>
      </div>

      {/* Mini Candidate Pipeline Bar Chart */}
      <div style={{ display: 'flex', gap: '6px', alignItems: 'flex-end', height: '60px', marginBottom: '20px', padding: '0 4px' }}>
        {[65, 48, 80, 35, 55, 72, 40, 58, 90].map((h, i) => (
          <motion.div
            key={i}
            initial={{ height: 0 }}
            animate={{ height: `${h}%` }}
            transition={{ duration: 0.8, delay: 0.3 + i * 0.1 }}
            style={{ flex: 1, borderRadius: '4px 4px 0 0', background: i === filled ? 'var(--cy-brand)' : 'rgba(10,102,194,0.15)' }}
          />
        ))}
      </div>

      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', color: 'var(--cy-text-mute)', fontFamily: 'JetBrains Mono', marginBottom: '16px' }}>
        <span>PIPELINE_FLOW</span>
        <motion.span key={filled} initial={{ opacity: 0 }} animate={{ opacity: 1 }} style={{ color: 'var(--cy-brand)', fontWeight: 700 }}>{filled}/9 Roles Active</motion.span>
      </div>

      <div className="cy-stat-chips">
        <div className="cy-stat-chip"><div className="cy-stat-chip-num">12</div><div className="cy-stat-chip-label">Listings</div></div>
        <div className="cy-stat-chip"><div className="cy-stat-chip-num">47</div><div className="cy-stat-chip-label">Reviewed</div></div>
        <div className="cy-stat-chip"><div className="cy-stat-chip-num">9</div><div className="cy-stat-chip-label">Hired</div></div>
      </div>
    </motion.div>
  );
};

const ApplicationTrackerCard = () => {
  const allStatuses = ["Applied", "Reviewed", "Interviewed", "Final Offer"];
  const [activeIdx, setActiveIdx] = useState(0);
  useEffect(() => {
    const interval = setInterval(() => setActiveIdx(p => (p + 1) % allStatuses.length), 2500);
    return () => clearInterval(interval);
  }, []);

  const progress = ((activeIdx + 1) / allStatuses.length) * 100;
  const circumference = 2 * Math.PI * 38;

  return (
    <motion.div
      className="cy-bouncing-card"
      style={{ bottom: '20px', right: '40px', width: '380px', zIndex: 6 }}
      animate={{ y: [0, -12, 0] }}
      transition={{ duration: 3.5, repeat: Infinity, ease: "easeInOut", delay: 0.5 }}
    >
      <div style={{ display: 'flex', gap: '24px', alignItems: 'center' }}>
        {/* Animated Circular Progress Ring */}
        <div style={{ position: 'relative', width: '90px', height: '90px', flexShrink: 0 }}>
          <svg width="90" height="90" viewBox="0 0 90 90">
            <circle cx="45" cy="45" r="38" fill="none" stroke="#F1F3F5" strokeWidth="6" />
            <motion.circle
              cx="45" cy="45" r="38" fill="none" stroke="var(--cy-brand)" strokeWidth="6"
              strokeLinecap="round"
              strokeDasharray={circumference}
              animate={{ strokeDashoffset: circumference - (circumference * progress) / 100 }}
              transition={{ duration: 0.8, ease: "easeOut" }}
              style={{ transform: 'rotate(-90deg)', transformOrigin: 'center' }}
            />
          </svg>
          <motion.div key={activeIdx} initial={{ scale: 0.5, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} style={{ position: 'absolute', top: 0, left: 0, right: 0, bottom: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '20px', fontWeight: 800, color: 'var(--cy-brand)', fontFamily: 'Space Grotesk' }}>
            {activeIdx + 1}/{allStatuses.length}
          </motion.div>
        </div>

        <div style={{ flex: 1 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <div style={{ fontWeight: 700, fontFamily: 'Space Grotesk', fontSize: '15px' }}>Application Pipeline</div>
            <motion.div animate={{ opacity: [1, 0.4, 1] }} transition={{ duration: 1.5, repeat: Infinity }} style={{ fontSize: '11px', fontWeight: 700, color: '#fff', background: '#EF4444', padding: '3px 10px', borderRadius: '99px' }}>● LIVE</motion.div>
          </div>
          <motion.div key={allStatuses[activeIdx]} initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }} style={{ fontSize: '22px', fontWeight: 700, color: 'var(--cy-brand)', marginBottom: '12px' }}>
            {allStatuses[activeIdx]}
          </motion.div>
        </div>
      </div>

      {/* Stage indicator dots */}
      <div style={{ display: 'flex', gap: '8px', marginTop: '16px' }}>
        {allStatuses.map((s, i) => (
          <div key={i} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '6px' }}>
            <motion.div animate={{ scale: i === activeIdx ? [1, 1.3, 1] : 1, backgroundColor: i <= activeIdx ? '#0A66C2' : '#F1F3F5' }} transition={{ duration: 1, repeat: i === activeIdx ? Infinity : 0 }} style={{ width: '12px', height: '12px', borderRadius: '50%' }} />
            <div style={{ fontSize: '10px', color: i <= activeIdx ? 'var(--cy-brand)' : 'var(--cy-text-mute)', fontWeight: i === activeIdx ? 700 : 400, fontFamily: 'JetBrains Mono' }}>{s.split(' ')[0]}</div>
          </div>
        ))}
      </div>
    </motion.div>
  );
};

// ======================================================================
// FEATURE CARDS WITH UNIQUE ANIMATIONS
// ======================================================================
// Card 1: Standard 3D Tilt
const TiltCard = ({ children, className, style }) => {
  const mx = useMotionValue(0);
  const my = useMotionValue(0);
  function onMove({ currentTarget, clientX, clientY }) {
    const { left, top, width, height } = currentTarget.getBoundingClientRect();
    mx.set((clientX - left - width / 2) / 15);
    my.set((clientY - top - height / 2) / 15);
  }
  return (
    <motion.div className={className} style={{ ...style, perspective: 800 }} onMouseMove={onMove} onMouseLeave={() => { mx.set(0); my.set(0); }}
      initial="rest" whileHover="hover" animate="rest"
      variants={{ rest: { backgroundColor: "rgba(255,255,255,0.75)", scale: 1 }, hover: { backgroundColor: "#0A66C2", scale: 1.03, boxShadow: "0px 32px 64px rgba(10,102,194,0.35)" } }}
      whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }}
      transition={{ type: "spring", stiffness: 300, damping: 20 }}>
      <motion.div style={{ width: "100%", height: "100%", rotateX: useSpring(useTransform(my, [-20, 20], [8, -8]), { stiffness: 300, damping: 30 }), rotateY: useSpring(useTransform(mx, [-20, 20], [-8, 8]), { stiffness: 300, damping: 30 }) }}>
        {children}
      </motion.div>
    </motion.div>
  );
};

// Pendulum Card: Hangs from top edge, swings gently like a clipboard
const PendulumCard = ({ children, className, style, delay = 0, amplitude = 3, speed = 6 }) => (
  <motion.div
    className={className}
    style={{ ...style, transformOrigin: 'top center' }}
    animate={{ rotate: [-amplitude, amplitude, -amplitude] }}
    transition={{ duration: speed, repeat: Infinity, ease: "easeInOut", delay }}
    whileHover={{ rotate: 0, scale: 1.03, backgroundColor: "#0A66C2", boxShadow: "0px 32px 64px rgba(10,102,194,0.35)" }}
    initial={{ backgroundColor: "rgba(255,255,255,0.75)" }}
  >
    {children}
  </motion.div>
);

// Text variants for hover color inversion
const vTitle = { rest: { color: "#001328" }, hover: { color: "#ffffff" } };
const vDesc = { rest: { color: "#6C7A89" }, hover: { color: "rgba(255,255,255,0.8)" } };

// ======================================================================
// DUAL ZIGZAG ROADMAP ENGINE
// ======================================================================
const ZigZagRoadmap = ({ steps, color }) => {
  const containerRef = useRef(null);
  const { scrollYProgress } = useScroll({ target: containerRef, offset: ["start center", "end center"] });
  const drawLine = useSpring(scrollYProgress, { stiffness: 100, damping: 30, restDelta: 0.001 });
  const dotY = useTransform(drawLine, [0, 1], ["0%", "100%"]);

  return (
    <div ref={containerRef} style={{ position: 'relative', padding: '50px 0' }}>
      {/* Background dashed center line */}
      <svg style={{ position: 'absolute', top: 0, left: 0, width: '100%', height: '100%', zIndex: 0 }}>
        <line x1="50%" y1="0" x2="50%" y2="100%" stroke="var(--cy-border)" strokeWidth="2" strokeDasharray="5 5" />
      </svg>
      {/* Animated drawn line */}
      <svg style={{ position: 'absolute', top: 0, left: 0, width: '100%', height: '100%', zIndex: 1, pointerEvents: 'none' }}>
        <motion.line x1="50%" y1="0" x2="50%" y2="100%" stroke={color} strokeWidth="4" style={{ pathLength: drawLine }} />
      </svg>
      {/* Pulsing Glowing Dot traveling down */}
      <motion.div style={{ position: 'absolute', left: '50%', top: dotY, transform: 'translate(-50%, -50%)', zIndex: 3 }}>
        <motion.div
          animate={{ scale: [1, 1.6, 1], opacity: [1, 0.6, 1] }}
          transition={{ duration: 1.5, repeat: Infinity }}
          style={{ width: '20px', height: '20px', borderRadius: '50%', background: color, boxShadow: `0 0 24px ${color}` }}
        />
      </motion.div>

      {steps.map((step, i) => {
        const isLeft = i % 2 === 0;
        return (
          <motion.div
            key={i}
            initial={{ opacity: 0, x: isLeft ? -80 : 80, scale: 0.85 }}
            whileInView={{ opacity: 1, x: 0, scale: 1 }}
            viewport={{ margin: "-80px", once: true }}
            transition={{ type: "spring", stiffness: 120, damping: 20, delay: 0.1 }}
            style={{
              display: 'flex',
              justifyContent: isLeft ? 'flex-start' : 'flex-end',
              marginBottom: '64px',
              paddingRight: isLeft ? '55%' : '0',
              paddingLeft: !isLeft ? '55%' : '0',
              position: 'relative',
              zIndex: 2
            }}
          >
            {/* Horizontal branch connector */}
            <svg style={{ position: 'absolute', top: '50%', transform: 'translateY(-50%)', left: isLeft ? '45%' : 'auto', right: !isLeft ? '45%' : 'auto', width: '10%', height: '2px', overflow: 'visible' }}>
              <motion.line x1="0" y1="0" x2="100%" y2="0" stroke={color} strokeWidth="2" initial={{ pathLength: 0 }} whileInView={{ pathLength: 1 }} viewport={{ once: true }} transition={{ delay: 0.3, duration: 0.6 }} />
              {/* Little endpoint dot */}
              <motion.circle cx={isLeft ? "0" : "100%"} cy="0" r="5" fill={color} initial={{ scale: 0 }} whileInView={{ scale: 1 }} viewport={{ once: true }} transition={{ delay: 0.6 }} />
            </svg>

            <motion.div
              className="cy-glass-panel"
              style={{ padding: '28px', background: 'rgba(255,255,255,0.95)', width: '100%' }}
              whileHover={{ scale: 1.05, boxShadow: `0 16px 48px ${color}33` }}
              transition={{ type: "spring", stiffness: 300, damping: 20 }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '16px', marginBottom: '12px' }}>
                <div style={{ width: '40px', height: '40px', borderRadius: '50%', background: color, color: '#fff', display: 'flex', alignItems: 'center', justifyContent: 'center', fontFamily: 'JetBrains Mono', fontWeight: 700, fontSize: '16px' }}>{i + 1}</div>
                <h4 style={{ fontSize: '18px', fontWeight: 700, color: 'var(--cy-brand-dark)' }}>{step.title}</h4>
              </div>
              <p style={{ color: 'var(--cy-text-mute)', fontSize: '14px', lineHeight: '1.6', paddingLeft: '56px' }}>{step.desc}</p>
            </motion.div>
          </motion.div>
        );
      })}
    </div>
  );
};

// ======================================================================
// MAIN APPLICATION
// ======================================================================
const Landing = () => {
  const containerRef = useRef(null);
  const [mousePos, setMousePos] = useState({ x: 0, y: 0 });

  useEffect(() => {
    const handleMouse = (e) => setMousePos({ x: e.clientX, y: e.clientY });
    window.addEventListener('mousemove', handleMouse);
    return () => window.removeEventListener('mousemove', handleMouse);
  }, []);

  const scrollToTop = (e) => { e.preventDefault(); window.scrollTo({ top: 0, left: 0, behavior: 'smooth' }); };

  const jobSeekerSteps = [
    { title: "Register & Verify OTP", desc: "Create your account and authenticate through our strict OTP verification system." },
    { title: "Build Encrypted Profile", desc: "Set up your bio, skills, experience. Upload your resume to the encrypted vault." },
    { title: "Search & Apply to Jobs", desc: "Filter by keywords, skills, location. Submit applications and track their status live." },
    { title: "Connect via E2EE Chat", desc: "Message recruiters directly through fully encrypted private conversations." }
  ];

  const recruiterSteps = [
    { title: "Create Company Page", desc: "Register your company with verified credentials and branding on FortKnox." },
    { title: "Post Job Listings", desc: "Publish roles with required skills, salary ranges, and application deadlines." },
    { title: "Review & Finalize", desc: "Evaluate candidates securely. Update status from Applied through to Offer." },
    { title: "Negotiate via E2EE", desc: "Reach out to top candidates through encrypted messaging channels." }
  ];

  return (
    <div className="cy-wrapper" ref={containerRef} id="home">
      <div className="cy-grid-bg"></div>
      <motion.div className="cy-glow" animate={{ x: mousePos.x - 300, y: mousePos.y - 300 }} transition={{ type: "tween", ease: "backOut", duration: 0.5 }} style={{ opacity: 0.4 }} />

      {/* ===== FULL-WIDTH NAVIGATION (Matched with Dashboard) ===== */}
      <nav className="app-nav">
        <Link to="/" onClick={scrollToTop} className="nav-brand">Fort<span>Knox</span></Link>
        
        <div className="nav-center">
          <a href="#home" onClick={scrollToTop}>Home</a>
          <a href="#features">Features</a>
          <a href="#roadmap">Roadmap</a>
          <a href="#contact">Contact Us</a>
        </div>
        
        <div className="nav-actions">
          <Link to="/login" className="btn-nav-outline">Login</Link>
          <Link to="/register" className="cy-btn cy-btn-primary" style={{ padding: '12px 24px', borderRadius: '4px' }}>Register</Link>
        </div>
      </nav>

      <div className="cy-container">

        {/* ===== HERO WITH BOUNCING CARDS ===== */}
        <section className="cy-hero">
          <motion.div className="cy-hero-left" initial={{ opacity: 0, y: 40 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.8 }}>
            <HUDFrame labelTopL="POS.X: 00 | POS.Y: 00" labelBotR="SEC_LVL_9.4">
              <h1 className="cy-h1">
                <span>Secure Job</span><br />
                <span style={{ color: 'var(--cy-brand)' }}>Search & Networking</span><br />
                <span>Platform.</span>
              </h1>
              <p className="cy-hero-p">
                Providing end-to-end security for professional interactions, private messaging, resume sharing, and job application workflows.
              </p>
              <div style={{ display: 'flex', gap: '16px' }}>
                <Link to="/register" className="cy-btn cy-btn-primary" style={{ padding: '16px 32px', fontSize: '15px' }}>Register Account &rarr;</Link>
                <a href="#features" className="cy-btn cy-btn-outline" style={{ padding: '16px 32px', fontSize: '15px' }}>Explore Platform</a>
              </div>
            </HUDFrame>
          </motion.div>

          <div className="cy-hero-right">
            <JobSeekerCard />
            <RecruiterCard />
            <ApplicationTrackerCard />
          </div>
        </section>

        {/* ===== FEATURES (5 Cards, Each Unique Animation) ===== */}
        <section className="cy-section" id="features">
          <motion.div initial={{ opacity: 0, y: 100 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true, margin: "-100px" }} transition={{ duration: 0.6 }}>
            <HUDFrame labelBotR="DATA.FRAME_1">
              <div className="cy-sec-header">
                <div className="cy-sec-num">01.</div>
                <h2 className="cy-sec-h2">What this platform does.</h2>
              </div>

              {/* Blue Mission Card with branching arrows */}
              <div style={{ position: 'relative', marginBottom: '60px' }}>
                <motion.div
                  initial={{ opacity: 0, y: 40 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  viewport={{ once: true }}
                  transition={{ duration: 0.8 }}
                  style={{
                    background: 'var(--cy-brand)',
                    borderRadius: '20px',
                    padding: '48px 56px',
                    position: 'relative',
                    overflow: 'visible',
                    boxShadow: '0 24px 64px rgba(10, 102, 194, 0.3)',
                  }}
                >
                  <div style={{ fontSize: '12px', color: 'rgba(255,255,255,0.6)', fontFamily: 'JetBrains Mono', marginBottom: '16px', letterSpacing: '2px' }}>CORE_MISSION</div>
                  <p style={{ fontSize: '26px', lineHeight: '1.6', fontWeight: 600, fontFamily: 'Space Grotesk, sans-serif', color: '#fff', margin: 0, maxWidth: '900px' }}>
                    FortKnox ensures confidentiality, integrity, and availability for user data by integrating OTP validation, PKI trust, and tamper-evident auditing into every layer.
                  </p>
                </motion.div>

                {/* Animated Branching Arrows SVG */}
                <svg width="100%" height="80" viewBox="0 0 1000 80" preserveAspectRatio="xMidYMin meet" style={{ display: 'block', overflow: 'visible' }}>
                  {/* Center trunk */}
                  <motion.line x1="500" y1="0" x2="500" y2="30" stroke="var(--cy-brand)" strokeWidth="3" initial={{ pathLength: 0 }} whileInView={{ pathLength: 1 }} viewport={{ once: true }} transition={{ duration: 0.4 }} />
                  {/* Horizontal spread */}
                  <motion.line x1="200" y1="30" x2="800" y2="30" stroke="var(--cy-brand)" strokeWidth="3" initial={{ pathLength: 0 }} whileInView={{ pathLength: 1 }} viewport={{ once: true }} transition={{ duration: 0.6, delay: 0.4 }} />
                  {/* Left branch down */}
                  <motion.line x1="200" y1="30" x2="200" y2="70" stroke="var(--cy-brand)" strokeWidth="3" initial={{ pathLength: 0 }} whileInView={{ pathLength: 1 }} viewport={{ once: true }} transition={{ duration: 0.3, delay: 1.0 }} />
                  {/* Right branch down */}
                  <motion.line x1="800" y1="30" x2="800" y2="70" stroke="var(--cy-brand)" strokeWidth="3" initial={{ pathLength: 0 }} whileInView={{ pathLength: 1 }} viewport={{ once: true }} transition={{ duration: 0.3, delay: 1.0 }} />
                  {/* Center branch down */}
                  <motion.line x1="500" y1="30" x2="500" y2="70" stroke="var(--cy-brand)" strokeWidth="3" initial={{ pathLength: 0 }} whileInView={{ pathLength: 1 }} viewport={{ once: true }} transition={{ duration: 0.3, delay: 1.0 }} />
                  {/* Arrow tips */}
                  {[200, 500, 800].map((cx, i) => (
                    <motion.polygon key={i} points={`${cx - 8},62 ${cx + 8},62 ${cx},78`} fill="var(--cy-brand)" initial={{ opacity: 0, scale: 0 }} whileInView={{ opacity: 1, scale: 1 }} viewport={{ once: true }} transition={{ delay: 1.3 + i * 0.1 }} style={{ transformOrigin: `${cx}px 70px` }} />
                  ))}
                </svg>
              </div>

              {/* Hanging Pendulum Feature Cards */}
              <div className="cy-bento">

                <PendulumCard className="cy-c-block span-6 cy-glass-panel" delay={0} amplitude={2.5} speed={5}>
                  <HUDFrame labelTopL="E2EE_CHAT">
                    <motion.div variants={vTitle} className="cy-c-title">End-to-End Chat</motion.div>
                    <motion.div variants={vDesc} className="cy-c-desc">Private messaging protected by E2EE. Server stores only ciphertext.</motion.div>
                  </HUDFrame>
                </PendulumCard>

                <PendulumCard className="cy-c-block span-6 cy-glass-panel" delay={0.8} amplitude={3} speed={7}>
                  <HUDFrame labelTopL="RESUME_VAULT">
                    <motion.div variants={vTitle} className="cy-c-title">Secure Resume Vault</motion.div>
                    <motion.div variants={vDesc} className="cy-c-desc">Resumes encrypted at rest. Strict RBAC access for owners and recruiters.</motion.div>
                  </HUDFrame>
                </PendulumCard>

                <PendulumCard className="cy-c-block span-4 cy-glass-panel" delay={0.3} amplitude={2} speed={6}>
                  <HUDFrame labelTopL="TRACKING">
                    <motion.div variants={vTitle} className="cy-c-title">Live Tracking</motion.div>
                    <motion.div variants={vDesc} className="cy-c-desc">Applied → Reviewed → Interviewed → Offer in real-time.</motion.div>
                  </HUDFrame>
                </PendulumCard>

                <PendulumCard className="cy-c-block span-4 cy-glass-panel" delay={1.2} amplitude={3.5} speed={8}>
                  <HUDFrame labelTopL="PKI_AUDIT">
                    <motion.div variants={vTitle} className="cy-c-title">PKI Auditing</motion.div>
                    <motion.div variants={vDesc} className="cy-c-desc">Tamper-evident hash-chained logs. Zero forgery tolerance.</motion.div>
                  </HUDFrame>
                </PendulumCard>

                <PendulumCard className="cy-c-block span-4 cy-glass-panel" delay={0.6} amplitude={2.8} speed={5.5}>
                  <HUDFrame labelTopL="OTP_VK">
                    <motion.div variants={vTitle} className="cy-c-title">OTP Virtual Keyboard</motion.div>
                    <motion.div variants={vDesc} className="cy-c-desc">High-risk actions verified by virtual keyboard OTP entry.</motion.div>
                  </HUDFrame>
                </PendulumCard>

              </div>
            </HUDFrame>
          </motion.div>
        </section>

        {/* ===== DUAL ZIGZAG ROADMAP ===== */}
        <section className="cy-section" id="roadmap">
          <motion.div initial={{ opacity: 0, y: 100 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true, margin: "-100px" }} transition={{ duration: 0.6 }}>
            <HUDFrame labelBotR="ROADMAP_VECTOR">
              <div className="cy-sec-header">
                <div className="cy-sec-num">02.</div>
                <h2 className="cy-sec-h2">Beginner's Guide Roadmap.</h2>
              </div>

              <p style={{ fontSize: '18px', color: 'var(--cy-text-mute)', marginBottom: '40px', maxWidth: '800px' }}>
                New to FortKnox? Scroll through the animated pipelines below to discover step-by-step workflows designed for your role.
              </p>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '120px', alignItems: 'start' }}>
                <div>
                  <h3 style={{ fontSize: '24px', color: 'var(--cy-brand)', fontFamily: 'Space Grotesk', fontWeight: 700, marginBottom: '20px' }}>🔍 For Job Seekers</h3>
                  <ZigZagRoadmap steps={jobSeekerSteps} color="var(--cy-brand)" />
                </div>
                <div style={{ paddingLeft: '40px' }}>
                  <h3 style={{ fontSize: '24px', color: 'var(--cy-brand-dark)', fontFamily: 'Space Grotesk', fontWeight: 700, marginBottom: '20px' }}>🏢 For Recruiters</h3>
                  <ZigZagRoadmap steps={recruiterSteps} color="var(--cy-brand-dark)" />
                </div>
              </div>
            </HUDFrame>
          </motion.div>
        </section>

        {/* ===== CONTACT US ===== */}
        <section className="cy-section" id="contact" style={{ borderBottom: 'none', paddingBottom: '120px' }}>
          <motion.div initial={{ opacity: 0, y: 100 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true, margin: "-100px" }} transition={{ duration: 0.6 }}>
            <HUDFrame labelBotR="COMM.LINK">
              <div className="cy-sec-header">
                <div className="cy-sec-num">03.</div>
                <h2 className="cy-sec-h2">Contact Us.</h2>
              </div>

              <div className="cy-bento">
                <div className="cy-c-block span-8 cy-glass-panel">
                  <h3 style={{ fontSize: '24px', fontFamily: 'Space Grotesk', fontWeight: 700, marginBottom: '24px' }}>Send us a message</h3>
                  <form onSubmit={(e) => e.preventDefault()}>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px' }}>
                      <div className="cy-input-group"><label>Full Name</label><input type="text" className="cy-input" placeholder="Enter your name" /></div>
                      <div className="cy-input-group"><label>Email Address</label><input type="email" className="cy-input" placeholder="name@domain.com" /></div>
                    </div>
                    <div className="cy-input-group"><label>Message</label><textarea className="cy-textarea" placeholder="How can we help?"></textarea></div>
                    <button type="submit" className="cy-btn cy-btn-primary" style={{ width: '100%', padding: '16px' }}>Send Message</button>
                  </form>
                </div>

                <div className="cy-c-block span-4 cy-glass-panel" style={{ background: 'var(--cy-brand-dark)', color: '#fff' }}>
                  <h3 style={{ fontSize: '24px', fontFamily: 'Space Grotesk', fontWeight: 700, marginBottom: '24px' }}>Need Help?</h3>
                  <p style={{ color: 'rgba(255,255,255,0.7)', fontSize: '15px', lineHeight: '1.6', marginBottom: '32px' }}>
                    For administrative support, account disputes, or platform moderation, please log in and navigate to your Settings page to contact the Admin or Superadmin directly.
                  </p>
                  <Link to="/login" className="cy-btn cy-btn-primary" style={{ width: '100%', border: '1px solid rgba(255,255,255,0.3)', padding: '16px' }}>Login to Access Settings</Link>
                </div>
              </div>
            </HUDFrame>
          </motion.div>
        </section>

      </div>
    </div>
  );
};

export default Landing;
