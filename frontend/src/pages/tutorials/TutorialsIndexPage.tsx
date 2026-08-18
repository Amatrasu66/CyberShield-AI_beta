import { BookOpen, GraduationCap } from 'lucide-react';
import { PageHeader } from '../../components/PageHeader';
import { Card } from '../../components/ui';
import { AreaCard } from '../../components/tutorials/AreaCard';
import { tutorialAreas } from '../../data/tutorialContent';

export function TutorialsIndexPage() {
  const ready = tutorialAreas.filter((area) => area.status === 'ready');
  const planned = tutorialAreas.filter((area) => area.status === 'planned');
  return (
    <>
      <PageHeader
        eyebrow="Learn"
        title="Tutorials"
        description="A documentation and education layer for every CyberShield AI tool — what it does, what its inputs and outputs mean, how the underlying module works, and how to use it safely."
      />
      <Card className="p-5">
        <div className="flex items-start gap-3">
          <GraduationCap className="mt-0.5 shrink-0 text-primary" size={20} />
          <div>
            <p className="font-display font-semibold">Documentation only</p>
            <p className="mt-1 text-sm leading-6 text-on-surface-variant">
              Tutorials teach the real, verified behavior of the console tools. Each area is a guided companion to a live page — it explains the tool without running any attack engine, keeping every safety boundary intact.
            </p>
          </div>
        </div>
      </Card>
      <h2 className="eyebrow mt-9">Learning paths</h2>
      <div className="mt-3 grid gap-5 sm:grid-cols-2 xl:grid-cols-3">
        {ready.map((area) => <AreaCard key={area.slug} area={area} />)}
      </div>
      <h2 className="eyebrow mt-9">Planned areas</h2>
      <div className="mt-3 grid gap-5 sm:grid-cols-2 xl:grid-cols-3">
        {planned.map((area) => <AreaCard key={area.slug} area={area} />)}
      </div>
      <p className="mt-9 flex items-start gap-2 text-xs leading-5 text-on-surface-variant">
        <BookOpen className="mt-0.5 shrink-0" size={14} />
        <span>Content is structured code-owned data rendered by dedicated components — no markdown pipeline, no user-generated lesson content.</span>
      </p>
    </>
  );
}