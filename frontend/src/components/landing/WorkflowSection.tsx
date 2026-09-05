import { useRef } from 'react';
import { motion, useReducedMotion, useScroll, useTransform, type MotionValue } from 'framer-motion';

interface StageData {
  readonly number: string;
  readonly title: string;
  readonly description: string;
}

const STAGES: readonly StageData[] = [
  {
    number: '01',
    title: 'SCAN',
    description: 'Identify the security surface and uncover potential weaknesses.',
  },
  {
    number: '02',
    title: 'ANALYZE',
    description: 'Examine findings, suspicious activity, and security signals.',
  },
  {
    number: '03',
    title: 'UNDERSTAND',
    description: 'Turn technical findings into clear, actionable context.',
  },
  {
    number: '04',
    title: 'ACT',
    description: 'Use the results to make informed security improvements.',
  },
];

interface StageProps {
  readonly stage: StageData;
  readonly index: number;
  readonly total: number;
  readonly progress: MotionValue<number>;
  readonly reducedMotion: boolean;
}

/**
 * One workflow stage. Activation is driven entirely by the shared section
 * scroll progress (MotionValues — no per-frame React state): the stage body
 * fades from muted to full, and the rail marker illuminates as the stage
 * travels through the viewport.
 */
function Stage({ stage, index, total, progress, reducedMotion }: StageProps) {
  const start = index / total;
  const bodyOpacity = useTransform(progress, [start, Math.min(start + 0.2, 1)], [0.4, 1]);
  const markerOpacity = useTransform(progress, [start, Math.min(start + 0.12, 1)], [0.2, 1]);

  return (
    <li className="relative py-7 first:pt-1 last:pb-1 sm:py-8 sm:first:pt-1 sm:last:pb-1">
      <motion.span
        aria-hidden="true"
        style={reducedMotion ? undefined : { opacity: markerOpacity }}
        className="absolute -left-8 top-9 h-2 w-2 rounded-full bg-primary sm:top-10"
      />
      <motion.div style={reducedMotion ? undefined : { opacity: bodyOpacity }}>
        <div className="grid grid-cols-[2.75rem_1fr] items-baseline gap-4">
          <span className="font-mono text-xs font-medium tracking-[0.16em] text-primary">
            {stage.number}
          </span>
          <h3 className="font-display text-xl font-bold tracking-tight text-on-surface sm:text-2xl">
            {stage.title}
          </h3>
        </div>
        <p className="mt-2 max-w-md pl-[3.75rem] text-sm leading-6 text-on-surface-variant">
          {stage.description}
        </p>
      </motion.div>
    </li>
  );
}

/**
 * Workflow — "From exposure to action."
 *
 * A quiet editorial timeline that decompresses after the dense Capabilities
 * stack: one continuous system of four stages with a subtle progress rail,
 * no cards, no dashboard chrome, no imagery.
 */
export function WorkflowSection() {
  const listRef = useRef<HTMLOListElement>(null);
  const { scrollYProgress } = useScroll({
    target: listRef,
    // NOTE: 'end end' (not 'end 0.5') — the stage list is shorter than the
    // viewport, so progress must complete when the list bottom reaches the
    // viewport bottom; otherwise the final stage can never fully activate.
    offset: ['start 0.8', 'end end'],
  });
  const reducedMotion = useReducedMotion() ?? false;

  return (
    <section
      aria-labelledby="landing-workflow-heading"
      id="workflow"
      data-testid="workflow-section"
      className="relative scroll-mt-24"
    >
      <div className="mx-auto grid max-w-6xl gap-10 px-4 py-16 sm:px-6 lg:grid-cols-[0.9fr_1.1fr] lg:gap-14 lg:px-8 lg:py-24">
        <div className="lg:sticky lg:top-28 lg:self-start">
          <p className="eyebrow mb-4">Workflow</p>
          <h2
            id="landing-workflow-heading"
            className="font-display text-3xl font-bold tracking-tight text-on-surface sm:text-4xl lg:text-[40px] lg:leading-[48px]"
          >
            From exposure
            <br />
            to action.
          </h2>
          <p className="mt-5 max-w-md text-sm leading-6 text-on-surface-variant">
            Each assessment moves through the same four stages.
          </p>
        </div>

        <div className="relative pl-8">
          <div aria-hidden="true" className="absolute bottom-3 left-[3px] top-3 w-px bg-border/50" />
          <motion.div
            aria-hidden="true"
            style={reducedMotion ? undefined : { scaleY: scrollYProgress }}
            className="absolute bottom-3 left-[3px] top-3 w-px origin-top bg-gradient-to-b from-primary via-primary to-tertiary"
          />
          <ol ref={listRef} className="divide-y divide-border/40">
            {STAGES.map((stage, index) => (
              <Stage
                key={stage.number}
                stage={stage}
                index={index}
                total={STAGES.length}
                progress={scrollYProgress}
                reducedMotion={reducedMotion}
              />
            ))}
          </ol>
        </div>
      </div>
    </section>
  );
}
