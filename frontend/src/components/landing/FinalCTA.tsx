import { useNavigate } from 'react-router-dom';
import { motion, useReducedMotion } from 'framer-motion';
import { ArrowRight } from 'lucide-react';
import { Button } from '../ui';

/**
 * Final CTA — centered editorial close adapted from the supplied 21st.dev
 * CallToAction (centered layout, large heading, supporting copy, restrained
 * single action). Simplified to one CTA: Get Started → /register.
 * No gradients, neon, cards, metrics, or canvas — just type and whitespace.
 */
export function FinalCTA() {
  const navigate = useNavigate();
  const reducedMotion = useReducedMotion() ?? false;

  return (
    <section
      aria-labelledby="landing-cta-heading"
      id="cta"
      data-testid="final-cta"
      className="relative scroll-mt-24 border-t border-border/40"
    >
      <motion.div
        initial={reducedMotion ? undefined : { opacity: 0, y: 16 }}
        whileInView={reducedMotion ? undefined : { opacity: 1, y: 0 }}
        viewport={{ once: true, margin: '-80px' }}
        transition={{ duration: 0.5, ease: 'easeOut' }}
        className="mx-auto max-w-2xl px-4 py-20 text-center sm:px-6 sm:py-24 lg:py-28"
      >
        <p className="eyebrow mb-4">Get started</p>
        <h2
          id="landing-cta-heading"
          className="font-display text-3xl font-bold tracking-tight text-on-surface sm:text-4xl lg:text-5xl lg:leading-[1.1]"
        >
          Know your exposure. Act with confidence.
        </h2>
        <p className="mx-auto mt-5 max-w-xl text-sm leading-6 text-on-surface-variant sm:text-base sm:leading-7">
          A focused workspace for security assessments, threat visibility, and practical remediation.
        </p>
        <div className="mt-8 flex justify-center">
          <Button type="button" onClick={() => void navigate('/register')} className="h-11 px-6">
            Get Started
            <ArrowRight size={16} aria-hidden="true" />
          </Button>
        </div>
      </motion.div>
    </section>
  );
}
