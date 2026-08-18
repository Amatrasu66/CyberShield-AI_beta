import { ArrowLeft, ArrowRight, ArrowUpRight } from 'lucide-react';
import { Link, useParams } from 'react-router-dom';
import { PageHeader } from '../../components/PageHeader';
import { Badge, Card } from '../../components/ui';
import { TutorialNotFound } from '../../components/tutorials/TutorialNotFound';
import { getTutorialArea } from '../../data/tutorialContent';

export function TutorialAreaPage() {
  const { area: areaSlug = '' } = useParams();
  const area = getTutorialArea(areaSlug);
  if (area === undefined) {
    return <TutorialNotFound message={`No tutorial area matches "${areaSlug}".`} />;
  }
  const Icon = area.icon;
  const ready = area.status === 'ready';
  return (
    <>
      <Link className="mb-6 inline-flex items-center gap-1 rounded text-sm text-on-surface-variant transition hover:text-on-surface focus:outline-none focus:ring-2 focus:ring-primary/60" to="/tutorials">
        <ArrowLeft size={14} /> All tutorials
      </Link>
      <PageHeader
        eyebrow={area.eyebrow}
        title={area.title}
        description={area.description}
        actions={
          area.toolPath !== null && (
            <Link className="inline-flex h-10 items-center justify-center gap-2 rounded bg-primary px-4 text-sm font-semibold text-primary-foreground transition hover:brightness-110 focus:outline-none focus:ring-2 focus:ring-primary/60" to={area.toolPath}>
              Open {area.toolLabel} <ArrowUpRight size={16} />
            </Link>
          )
        }
      />
      <Card className="p-5">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <span className="grid h-11 w-11 place-items-center rounded-lg bg-primary/15 text-primary">
              <Icon size={22} />
            </span>
            <div>
              <p className="font-display font-semibold">{area.title}</p>
              <p className="text-xs text-on-surface-variant">{ready ? `${area.lessons.length} lesson${area.lessons.length === 1 ? '' : 's'}` : 'Planned area'}</p>
            </div>
          </div>
          <Badge tone={ready ? 'primary' : 'warning'}>{ready ? 'Ready' : 'Planned'}</Badge>
        </div>
        {!ready && (
          <p className="mt-4 text-sm leading-6 text-on-surface-variant">
            This area is reserved for AI/ML model-backed analysis. It will be documented when the feature is actually implemented. Today, every analyzer in the console is rule-based — the model files in the project are placeholders.
          </p>
        )}
      </Card>
      {ready && (
        <>
          <h2 className="eyebrow mt-8">Lessons</h2>
          <div className="mt-3 grid gap-5 md:grid-cols-2">
            {area.lessons.map((lesson) => (
              <Card key={lesson.id} className="group p-5">
                <Link className="rounded focus:outline-none focus:ring-2 focus:ring-primary/60" to={`/tutorials/${area.slug}/${lesson.id}`}>
                  <span className="block font-display text-lg font-semibold text-on-surface">{lesson.title}</span>
                  <span className="mt-1 block text-sm leading-6 text-on-surface-variant">{lesson.summary}</span>
                  <span className="mt-4 inline-flex items-center gap-1 text-sm font-semibold text-primary">
                    Read lesson <ArrowRight className="transition-transform group-hover:translate-x-0.5" size={15} />
                  </span>
                </Link>
              </Card>
            ))}
          </div>
        </>
      )}
    </>
  );
}