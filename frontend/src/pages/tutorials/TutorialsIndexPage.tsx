import { ArrowRight, BookOpen, Compass, GraduationCap } from 'lucide-react';
import { Link } from 'react-router-dom';
import { PageHeader } from '../../components/PageHeader';
import { Card } from '../../components/ui';
import { AreaCard } from '../../components/tutorials/AreaCard';
import { tutorialAreas } from '../../data/tutorialContent';

const categoryGroups: ReadonlyArray<{ title: string; eyebrow: string; slugs: readonly string[] }> = [
  { title: 'Getting started', eyebrow: 'Start here', slugs: ['getting-started', 'glossary'] },
  { title: 'Network security', eyebrow: 'Ports & threat', slugs: ['port-scanner', 'ip-reputation', 'threat-intelligence', 'threat-assessment'] },
  { title: 'Web security', eyebrow: 'Web', slugs: ['website-scanner'] },
  { title: 'Authentication & passwords', eyebrow: 'Identity', slugs: ['password-analyzer', 'phishing-detector', 'authentication'] },
  { title: 'Logs & monitoring', eyebrow: 'Telemetry', slugs: ['log-analyzer', 'dashboard', 'reports'] },
  { title: 'Cryptography & labs', eyebrow: 'Security lab', slugs: ['cryptography-lab', 'sql-playground'] },
];

export function TutorialsIndexPage() {
  const ready = tutorialAreas.filter((area) => area.status === 'ready');
  const planned = tutorialAreas.filter((area) => area.status === 'planned');
  return (
    <>
      <PageHeader
        eyebrow="Learn"
        title="Tutorials"
        description="A documentation and education layer for every CyberShield tool — what it does, what its inputs and outputs mean, how the underlying module works, and how to use it safely. Written for beginners: every concept is introduced before instructions."
      />
      {/* BEGINNER ONBOARDING — Start here */}
      <Card className="p-5 border-primary/20 bg-primary/[0.03]">
        <div className="flex items-start gap-3">
          <span className="grid h-9 w-9 place-items-center rounded-lg bg-primary/15 text-primary shrink-0">
            <Compass size={18} />
          </span>
          <div className="flex-1 min-w-0">
            <p className="eyebrow text-primary">New to cybersecurity?</p>
            <h2 className="font-display text-lg font-semibold mt-1">Start here — 5 concepts in 5 minutes</h2>
            <p className="mt-2 text-sm leading-6 text-on-surface-variant">
              No networking knowledge needed. Learn what an IP address, port, attack surface, security scan, and security score mean — then every tool will make sense.
            </p>
            <div className="mt-4 grid gap-2 sm:grid-cols-5 text-xs font-mono">
              <span className="rounded border bg-surface-low px-2 py-1 text-center">IP address</span>
              <span className="rounded border bg-surface-low px-2 py-1 text-center">Port</span>
              <span className="rounded border bg-surface-low px-2 py-1 text-center">Security scan</span>
              <span className="rounded border bg-surface-low px-2 py-1 text-center">Attack surface</span>
              <span className="rounded border bg-surface-low px-2 py-1 text-center">Security score</span>
            </div>
            <div className="mt-4 flex flex-wrap gap-2">
              <Link to="/tutorials/getting-started/new-to-cybersecurity" className="inline-flex h-9 items-center justify-center gap-2 rounded bg-primary px-4 text-sm font-semibold text-primary-foreground hover:brightness-110 focus:outline-none focus:ring-2 focus:ring-primary/60">
                Start the beginner guide <ArrowRight size={15} />
              </Link>
              <Link to="/tutorials/glossary/terms" className="inline-flex h-9 items-center justify-center gap-2 rounded border bg-surface-low px-4 text-sm font-medium hover:bg-surface-high focus:outline-none focus:ring-2 focus:ring-primary/60">
                <BookOpen size={14} /> Open glossary
              </Link>
            </div>
          </div>
        </div>
      </Card>

      {/* What tools map to which tutorials */}
      <Card className="p-5 mt-5">
        <div className="flex items-start gap-3">
          <GraduationCap className="mt-0.5 shrink-0 text-primary" size={20} />
          <div>
            <p className="font-display font-semibold">Documentation only — verified behavior</p>
            <p className="mt-1 text-sm leading-6 text-on-surface-variant">
              Tutorials teach the real, verified behavior of the console tools. Each area is a guided companion to a live page — it explains the tool without running any attack engine, keeping every safety boundary intact.
              Only scan systems you own or have explicit permission to test.
            </p>
          </div>
        </div>
      </Card>

      {/* GROUPED LEARNING PATHS */}
      {categoryGroups.map((group) => {
        const areas = group.slugs.map((s) => ready.find((a) => a.slug === s)).filter(Boolean) as typeof ready;
        if (areas.length === 0) return null;
        return (
          <div key={group.title} className="mt-9">
            <h2 className="eyebrow">{group.eyebrow} · {group.title}</h2>
            <div className="mt-3 grid gap-5 sm:grid-cols-2 xl:grid-cols-3">
              {areas.map((area) => (
                <AreaCard key={area.slug} area={area} />
              ))}
            </div>
          </div>
        );
      })}

      {/* Any remaining ready areas not in groups (fallback) */}
      {(() => {
        const groupedSlugs = new Set(categoryGroups.flatMap((g) => g.slugs));
        const remaining = ready.filter((a) => !groupedSlugs.has(a.slug));
        if (remaining.length === 0) return null;
        return (
          <div className="mt-9">
            <h2 className="eyebrow">More tutorials</h2>
            <div className="mt-3 grid gap-5 sm:grid-cols-2 xl:grid-cols-3">
              {remaining.map((area) => (
                <AreaCard key={area.slug} area={area} />
              ))}
            </div>
          </div>
        );
      })()}

      {planned.length > 0 && (
        <>
          <h2 className="eyebrow mt-9">Planned areas</h2>
          <div className="mt-3 grid gap-5 sm:grid-cols-2 xl:grid-cols-3">
            {planned.map((area) => (
              <AreaCard key={area.slug} area={area} />
            ))}
          </div>
        </>
      )}

      <p className="mt-9 flex items-start gap-2 text-xs leading-5 text-on-surface-variant">
        <BookOpen className="mt-0.5 shrink-0" size={14} />
        <span>Content is structured code-owned data rendered by dedicated components — no markdown pipeline, no user-generated lesson content. Providers shown are only those actually enabled: AbuseIPDB and, when configured, Project Honey Pot. GrayNoise is not used.</span>
      </p>
    </>
  );
}
