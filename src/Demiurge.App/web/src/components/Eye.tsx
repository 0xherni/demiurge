import { useEffect, useRef, useState } from "react";

const ALMOND_SMALL = "M1.5 16 Q16 1 30.5 16 Q16 31 1.5 16 Z";
const ALMOND = "M8 66 Q66 6 124 66 Q66 126 8 66 Z";

/** Ícono chico: ojo rojo de pupila vertical. */
export function Sigil({ size = 26 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden="true">
      <defs>
        <clipPath id="sigil-clip"><path d={ALMOND_SMALL} /></clipPath>
      </defs>
      <path d={ALMOND_SMALL} fill="#0a0707" />
      <g clipPath="url(#sigil-clip)">
        <circle cx="16" cy="16" r="6.2" fill="#d11a2a" />
        <ellipse cx="16" cy="16" rx="1.4" ry="5" fill="#0a0707" />
        <circle cx="18.3" cy="13.6" r="1" fill="#ede5e3" />
      </g>
      <path d={ALMOND_SMALL} fill="none" stroke="#d11a2a" strokeWidth="1.6" strokeLinejoin="round" />
    </svg>
  );
}

const GAZE_X = 9;
const GAZE_Y = 3.5;
const reduceMotion = typeof matchMedia !== "undefined" && matchMedia("(prefers-reduced-motion: reduce)").matches;

/**
 * Ojo grande del Inicio. No sigue al mouse: casi siempre mira al frente y cada 4–9 s desvía la mirada un poco,
 * lento, como quien acecha. De vez en cuando la pupila se afina (el toque de maldad). Escaneando, se mueve más
 * y la pupila se dilata.
 */
export function EyeBig({ scanning }: { scanning: boolean }) {
  const [gaze, setGaze] = useState({ x: 0, y: 0 });
  const [squint, setSquint] = useState(false);
  const scanningRef = useRef(scanning);
  scanningRef.current = scanning;

  useEffect(() => {
    if (reduceMotion) return;
    let next = 0;
    let nextSquint = performance.now() + 9000;
    let squintUntil = 0;
    let current = { x: 0, y: 0 };
    const timer = setInterval(() => {
      const now = performance.now();
      const scan = scanningRef.current;
      if (!scan && now >= nextSquint) {
        squintUntil = now + 1800 + Math.random() * 1400;
        nextSquint = now + 14000 + Math.random() * 12000;
      }
      setSquint(!scan && now < squintUntil);
      if (now < next) return;
      if (scan) {
        current = { x: (Math.random() * 2 - 1) * GAZE_X * 1.2, y: (Math.random() * 2 - 1) * GAZE_Y };
        next = now + 1100 + Math.random() * 900;
      } else {
        const looking = current.x !== 0 || current.y !== 0;
        if (looking && Math.random() < 0.6) current = { x: 0, y: 0 };
        else {
          const side = Math.random() < 0.5 ? -1 : 1;
          current = { x: side * GAZE_X * (0.5 + Math.random() * 0.5), y: (Math.random() * 2 - 1) * GAZE_Y };
        }
        next = now + 4000 + Math.random() * 5000;
      }
      setGaze(current);
    }, 250);
    return () => clearInterval(timer);
  }, []);

  return (
    <div className="sigil-big">
      <svg viewBox="0 0 132 132" aria-hidden="true">
        <defs>
          <clipPath id="eye-clip"><path d={ALMOND} /></clipPath>
          <radialGradient id="eye-glow">
            <stop offset="0" stopColor="#d11a2a" stopOpacity=".9" />
            <stop offset="1" stopColor="#d11a2a" stopOpacity="0" />
          </radialGradient>
        </defs>
        <ellipse className="glow" cx="66" cy="68" rx="66" ry="44" fill="url(#eye-glow)" />
        <g className={`eye ${scanning ? "eye-scan" : "eye-rest"} ${squint ? "squint" : ""}`}>
          <path d={ALMOND} fill="var(--ink)" />
          <g clipPath="url(#eye-clip)">
            <g className="iris" style={{ transform: `translate(${gaze.x.toFixed(1)}px, ${gaze.y.toFixed(1)}px)` }}>
              <circle cx="66" cy="66" r="25" fill="var(--blood)" />
              <circle cx="66" cy="66" r="25" fill="none" stroke="var(--blood-deep)" strokeWidth="3" />
              <circle cx="66" cy="66" r="15" fill="none" stroke="var(--blood-deep)" strokeWidth="1" opacity=".6" />
              <ellipse className="pupil" cx="66" cy="66" rx="5" ry="20" fill="var(--void)" />
              <circle cx="76" cy="57" r="2.6" fill="var(--bone)" />
            </g>
          </g>
          <path d={ALMOND} fill="none" stroke="var(--blood)" strokeWidth="2.5" strokeLinejoin="round" />
        </g>
      </svg>
    </div>
  );
}
