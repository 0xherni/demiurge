import type { ReactNode } from "react";

const PATHS: Record<string, ReactNode> = {
  home: <path d="M3 8.5 8 4l5 4.5V13H3z" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round" />,
  findings: (
    <>
      <path d="M8 2.5 14 13H2z" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round" />
      <path d="M8 6.5v3M8 11.2v.1" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
    </>
  ),
  inventory: (
    <>
      <rect x="2.5" y="3" width="11" height="3" rx="1" fill="none" stroke="currentColor" strokeWidth="1.4" />
      <rect x="2.5" y="8" width="11" height="5" rx="1" fill="none" stroke="currentColor" strokeWidth="1.4" />
    </>
  ),
  news: (
    <>
      <circle cx="8" cy="8" r="5.5" fill="none" stroke="currentColor" strokeWidth="1.4" />
      <path d="M8 5v3.2l2 1.3" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
    </>
  ),
  activity: <path d="M2 9h3l2-5 2.5 8L11 8h3" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round" strokeLinecap="round" />,
  settings: (
    <>
      <circle cx="8" cy="8" r="2.2" fill="none" stroke="currentColor" strokeWidth="1.4" />
      <path d="M8 2v2M8 12v2M2 8h2M12 8h2M3.8 3.8l1.4 1.4M10.8 10.8l1.4 1.4M3.8 12.2l1.4-1.4M10.8 5.2l1.4-1.4" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
    </>
  ),
};

export function Icon({ name }: { name: string }) {
  return <svg className="ico" viewBox="0 0 16 16" aria-hidden="true">{PATHS[name]}</svg>;
}
