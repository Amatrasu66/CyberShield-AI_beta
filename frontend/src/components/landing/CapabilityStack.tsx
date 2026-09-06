import { useRef, type CSSProperties } from 'react';
import { motion, useReducedMotion, useScroll, useTransform } from 'framer-motion';
import type { MotionValue } from 'framer-motion';
import {
  Database,
  FileBarChart,
  KeyRound,
  LockKeyhole,
  Network,
  ScanLine,
  ScrollText,
  ShieldAlert,
} from 'lucide-react';
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
    icon: LockKeyhole,
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
}

/**
 * One card in the Skiper-style pile. Each wrapper is a direct sticky child
 * of the tall stack container, so earlier cards pin to the viewport while
 * later cards scroll up and cover them. Scale is derived from the shared
 * scroll progress (a MotionValue — no per-frame React state): the first
 * card settles smallest, the last stays at 1.0, giving clear depth.
 */
function StackCard({ capability, index, total, progress }: StackCardProps) {
  const targetScale = 1 - (total - 1 - index) * 0.05;
  const scale = useTransform(progress, [index / total, 1], [1, targetScale]);

  return (
    <div
      className="sticky top-[calc(4.5rem+var(--stack-offset))] mb-[7svh] last:mb-0 lg:top-[calc(5.5rem+var(--stack-offset))]"
      style={{ '--stack-offset': `${index * 0.875}rem`, zIndex: index } as CSSProperties}
    >
      <motion.div style={{ scale }} className="origin-top will-change-transform">
        <CapabilityCard capability={capability} index={index} total={total} />
      </motion.div>
    </div>
  );
}

/**
 * Eight-card sticky pile adapted from the Skiper16 mechanics (useScroll +
 * per-card useTransform + sticky positioning) to the page's native document
 * scroll. The container is a tall scroll region: Card 01 is the only
 * fully-visible card on entry, and Cards 02–08 progressively slide over the
 * pinned stack as the user scrolls. No Lenis, no nested scroll containers,
 * no images or canvas, no new dependencies.
 */
export function CapabilityStack() {
  const container = useRef<HTMLDivElement>(null);
  const { scrollYProgress } = useScroll({
    target: container,
    offset: ['start start', 'end end'],
  });
  const reducedMotion = useReducedMotion() ?? false;

  if (reducedMotion) {
    return (
      <div className="grid gap-5" data-testid="capability-stack">
        {CAPABILITIES.map((capability, index) => (
          <CapabilityCard
            key={capability.number}
            capability={capability}
            index={index}
            total={CAPABILITIES.length}
          />
        ))}
      </div>
    );
  }

  return (
    <div
      ref={container}
      className="relative pt-[6svh] pb-[10svh]"
      data-testid="capability-stack"
    >
      {CAPABILITIES.map((capability, index) => (
        <StackCard
          key={capability.number}
          capability={capability}
          index={index}
          total={CAPABILITIES.length}
          progress={scrollYProgress}
        />
      ))}
    </div>
  );
}
