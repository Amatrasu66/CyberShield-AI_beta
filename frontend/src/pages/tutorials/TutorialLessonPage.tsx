import { ArrowLeft, ArrowUpRight } from 'lucide-react';
import { Link, useParams } from 'react-router-dom';
import { PageHeader } from '../../components/PageHeader';
import { Badge, Card } from '../../components/ui';
import { LessonPager } from '../../components/tutorials/LessonPager';
import { LessonSectionView } from '../../components/tutorials/LessonSectionView';
import { TutorialNotFound } from '../../components/tutorials/TutorialNotFound';
import { getTutorialArea } from '../../data/tutorialContent';

export function TutorialLessonPage() {
  const { area: areaSlug = '', lesson: lessonId = '' } = useParams();
  const area = getTutorialArea(areaSlug);
  const lesson = area?.lessons.find((item) => item.id === lessonId);
  if (area === undefined || lesson === undefined) {
    return <TutorialNotFound message={`The tutorial "${lessonId}" was not found in the "${areaSlug}" area.`} />;
  }
  const Icon = area.icon;
  const asideLinkClass = 'flex items-center justify-between gap-2 rounded border bg-surface-low p-3 text-sm font-semibold text-on-surface transition hover:border-primary/40 hover:text-primary focus:outline-none focus:ring-2 focus:ring-primary/60';
  const lessonLinkClass = (id: string) => (id === lesson.id
    ? 'flex items-start gap-2 rounded p-2 text-sm leading-6 bg-primary/10 text-primary focus:outline-none focus:ring-2 focus:ring-primary/60'
    : 'flex items-start gap-2 rounded p-2 text-sm leading-6 text-on-surface-variant transition hover:bg-surface-high hover:text-on-surface focus:outline-none focus:ring-2 focus:ring-primary/60');
  return (
    <>
      <Link className="mb-6 inline-flex items-center gap-1 rounded text-sm text-on-surface-variant transition hover:text-on-surface focus:outline-none focus:ring-2 focus:ring-primary/60" to={`/tutorials/${area.slug}`}>
        <ArrowLeft size={14} /> Back to {area.title}
      </Link>
      <PageHeader
        eyebrow={`${area.eyebrow} · ${area.title}`}
        title={lesson.title}
        description={lesson.summary}
        actions={
          area.toolPath !== null && (
            <Link className="inline-flex h-10 items-center justify-center gap-2 rounded bg-primary px-4 text-sm font-semibold text-primary-foreground transition hover:brightness-110 focus:outline-none focus:ring-2 focus:ring-primary/60" to={area.toolPath}>
              Open {area.toolLabel} <ArrowUpRight size={16} />
            </Link>
          )
        }
      />
      <div className="grid gap-5 lg:grid-cols-[1fr_320px]">
        <div className="space-y-5">
          {lesson.sections.map((section, index) => (
            <Card className="p-5" key={`${section.kind}-${index}`}>
              <LessonSectionView section={section} />
            </Card>
          ))}
          {lesson.related !== undefined && lesson.related.length > 0 && (
            <Card className="p-5">
              <h2 className="font-display font-semibold">Keep exploring</h2>
              <ul className="mt-3 space-y-2">
                {lesson.related.map((item) => (
                  <li key={item.to}>
                    <Link className="inline-flex items-center gap-1 rounded text-sm text-primary focus:outline-none focus:ring-2 focus:ring-primary/60 hover:underline" to={item.to}>
                      {item.label} <ArrowUpRight size={13} />
                    </Link>
                  </li>
                ))}
              </ul>
            </Card>
          )}
          <LessonPager areaSlug={area.slug} current={lesson} lessons={area.lessons} />
        </div>
        <aside className="space-y-5 lg:sticky lg:top-6 lg:self-start">
          <Card className="p-5">
            <div className="flex items-center gap-3">
              <span className="grid h-10 w-10 place-items-center rounded-lg bg-primary/15 text-primary">
                <Icon size={20} />
              </span>
              <div>
                <p className="font-display font-semibold">{area.title}</p>
                <div className="mt-1"><Badge tone={area.status === 'ready' ? 'primary' : 'warning'}>{area.status === 'ready' ? 'Ready' : 'Planned'}</Badge></div>
              </div>
            </div>
            {area.toolPath !== null && (
              <Link className={`mt-4 ${asideLinkClass}`} to={area.toolPath}>
                Open {area.toolLabel} <ArrowUpRight size={15} className="shrink-0" />
              </Link>
            )}
          </Card>
          {area.lessons.length > 1 && (
            <Card className="p-5">
              <p className="eyebrow mb-3">In this area</p>
              <ol className="space-y-0.5">
                {area.lessons.map((item, index) => (
                  <li key={item.id}>
                    <Link className={lessonLinkClass(item.id)} to={`/tutorials/${area.slug}/${item.id}`}>
                      <span className="mt-0.5 font-mono text-[11px]">{index + 1}</span>
                      <span>{item.title}</span>
                    </Link>
                  </li>
                ))}
              </ol>
            </Card>
          )}
        </aside>
      </div>
    </>
  );
}