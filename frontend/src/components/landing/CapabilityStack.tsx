import { useRef, type CSSProperties } from 'react';
import { motion, useReducedMotion, useScroll, useTransform } from 'framer-motion';
import type { MotionValue } from 'framer-motion';
import {
  Binary,
  Database,
  FileBarChart,
  KeyRound,
  Network,
  ScanLine,
  ScrollText,
  ShieldAlert,
} from 'lucide-react';
import { cn } from '../../utils/cn';
import { CapabilityCard, type Capability } from './CapabilityCard';

const CAPABILITIES: readonly Capability[] = [
  {
    number: '01',
    title: 'Website Security Scanner',
    description: 'Assess a website for common security weaknesses and configuration issues.',
    to: '/website-scanner',
    action: 'Open Scanner',
    icon: ScanLine,
  },
  {
    number: '02',
    title: 'Phishing Detection',
    description: 'Analyze suspicious URLs and messages for phishing indicators.',
    to: '/phishing-detector',
    action: 'Open Detector',
    icon: ShieldAlert,
  },
  {
    number: '03',
    title: 'Password Analysis',
    description: 'Evaluate password strength and identify common weaknesses.',
    to: '/password-analyzer',
    action: 'Open Analyzer',
    icon: KeyRound,
  },
  {
    number: '04',
    title: 'Log Analysis',
    description: 'Inspect security logs for suspicious patterns and events.',
    to: '/log-analyzer',
    action: 'Open Analyzer',
    icon: ScrollText,
  },
  {
    number: '05',
    title: 'Port Scanner',
    description: 'Discover reachable network ports for authorized security assessment.',
    to: '/port-scanner',
    action: 'Open Scanner',
    icon: Network,
  },
  {
    number: '06',
    title: 'SQL Playground',
    description: 'Practice SQL concepts and explore query behavior in a controlled environment.',
    to: '/sql-playground',
    action: 'Open Playground',
    icon: Database,
  },
  {
    number: '07',
    title: 'Cryptography Lab',
    description: 'Explore cryptographic algorithms and security concepts interactively.',
    to: '/cryptography-lab',
    action: 'Open Lab',
    icon: Binary,
  },
  {
    number: '08',
    title: 'Security Reports',
    description: 'Review and organize findings from security assessments.',
    to: '/reports',
    action: 'View Reports',
    icon: FileBarChart,
  },
];

interface StackCardProps {
  readonly capability: Capability;
  readonly index: number;
  readonly total: number;
  readonly progress: MotionValue<number>;
  readonly reducedMotion: boolean;
}

/**
 * One sticky card in the stack. Scale is derived from shared scroll progress
 * (a MotionValue — no per-frame React state). First card settles at ~0.72,
 * last card stays at 1.0.
 */
function StackCard({ capability, index, total, progress, reducedMotion }: StackCardProps) {
  const targetScale = 1 - (total - 1 - index) * 0.04;
  const scale = useTransform(progress, [index / total, 1], [1, targetScale]);

  return (
    <div
      className={cn('mb-6 last:mb-0', !reducedMotion && 'sticky top-[calc(4.5rem+var(--card-index)*0.75rem)] lg:top-[calc(6rem+var(--card-index)*1.5rem)]')}
      style={{ '--card-index': index } as CSSProperties}
    >
      <motion.div style={reducedMotion ? undefined : { scale }} className="origin-top">
        <CapabilityCard capability={capability} />
      </motion.div>
    </div>
  );
}

/**
 * Eight-card sticky stack adapted from the Skiper16 mechanics (useScroll +
 * useTransform + sticky positioning) to the page's native document scroll.
 * No Lenis, no nested scroll containers, no images or canvas.
 */
export function CapabilityStack() {
  const container = useRef<HTMLDivElement>(null);
  const { scrollYProgress } = useScroll({
    target: container,
    offset: ['start start', 'end end'],
  });
  const reducedMotion = useReducedMotion() ?? false;

  return (
    <div ref={container} className="relative" data-testid="capability-stack">
      {CAPABILITIES.map((capability, index) => (
        <StackCard
          key={capability.number}
          capability={capability}
          index={index}
          total={CAPABILITIES.length}
          progress={scrollYProgress}
          reducedMotion={reducedMotion}
        />
      ))}
    </div>
  );
}
