import type {ReactNode} from 'react';
import {useId} from 'react';

type MacHardwareProps = {
  kind: 'mini' | 'studio';
  className?: string;
};

/**
 * An original isometric drawing of a Mac mini or Mac Studio in aluminium (not Apple artwork).
 * Rounded corners come from stroking each face in its own colour with a round line join.
 */
export default function MacHardware({kind, className}: MacHardwareProps): ReactNode {
  const id = useId().replace(/:/g, '');
  const h = kind === 'studio' ? 104 : 40;
  const top = 'M60 110 L200 58 L340 110 L200 162 Z';
  const left = `M60 110 L200 162 L200 ${162 + h} L60 ${110 + h} Z`;
  const right = `M200 162 L340 110 L340 ${110 + h} L200 ${162 + h} Z`;
  const floor = 162 + h;
  return (
    <svg
      className={className}
      viewBox={`0 0 400 ${floor + 50}`}
      role="img"
      aria-label={kind === 'studio' ? 'Mac Studio illustration' : 'Mac mini illustration'}>
      <defs>
        <linearGradient id={`${id}top`} x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#fbfbfd" />
          <stop offset="0.6" stopColor="#e6e6ea" />
          <stop offset="1" stopColor="#d2d2d7" />
        </linearGradient>
        <linearGradient id={`${id}left`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="#d9d9de" />
          <stop offset="1" stopColor="#b4b4ba" />
        </linearGradient>
        <linearGradient id={`${id}right`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="#c4c4ca" />
          <stop offset="1" stopColor="#97979e" />
        </linearGradient>
        <radialGradient id={`${id}shadow`} cx="50%" cy="50%" r="50%">
          <stop offset="0" stopColor="#000" stopOpacity="0.55" />
          <stop offset="1" stopColor="#000" stopOpacity="0" />
        </radialGradient>
        <linearGradient id={`${id}sheen`} x1="0" y1="0" x2="1" y2="0">
          <stop offset="0" stopColor="#fff" stopOpacity="0" />
          <stop offset="0.5" stopColor="#fff" stopOpacity="0.9" />
          <stop offset="1" stopColor="#fff" stopOpacity="0" />
        </linearGradient>
      </defs>
      <ellipse cx="200" cy={floor + 8} rx="175" ry="30" fill={`url(#${id}shadow)`} />
      <path d={left} fill={`url(#${id}left)`} stroke={`url(#${id}left)`} strokeWidth="18" strokeLinejoin="round" />
      <path d={right} fill={`url(#${id}right)`} stroke={`url(#${id}right)`} strokeWidth="18" strokeLinejoin="round" />
      <path d={top} fill={`url(#${id}top)`} stroke={`url(#${id}top)`} strokeWidth="18" strokeLinejoin="round" />
      <path d="M76 112 L200 66 L324 112" fill="none" stroke={`url(#${id}sheen)`} strokeWidth="1.5" opacity="0.8" />
      {/* Front ports on the left face, LED on the right */}
      <g fill="#3a3a3c" opacity="0.85">
        <rect x="0" y="0" width="16" height="5" rx="2.5" transform={`translate(96 ${130 + h * 0.62}) rotate(20)`} />
        <rect x="0" y="0" width="16" height="5" rx="2.5" transform={`translate(120 ${139 + h * 0.62}) rotate(20)`} />
        {kind === 'studio' ? (
          <rect x="0" y="0" width="40" height="3.5" rx="1.75" transform={`translate(146 ${150 + h * 0.62}) rotate(20)`} />
        ) : (
          <circle cx="152" cy={152 + h * 0.62} r="3" />
        )}
      </g>
      <circle className="mac-led" cx="318" cy={118 + h * 0.75} r="3" fill="#30d158" />
    </svg>
  );
}
