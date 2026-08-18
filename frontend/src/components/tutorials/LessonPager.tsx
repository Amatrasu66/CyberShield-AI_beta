import { ArrowLeft, ArrowRight } from 'lucide-react';
import { Link } from 'react-router-dom';
import type { TutorialLesson } from '../../types/tutorials';

export interface LessonPagerProps {
  readonly areaSlug: string;
  readonly lessons: readonly TutorialLesson[];
  readonly current: TutorialLesson;
}

export function LessonPager({ areaSlug, lessons, current }: LessonPagerProps) {
  const index = lessons.findIndex((lesson) => lesson.id === current.id);
  const previous = index > 0 ? lessons[index - 1] : undefined;
  const next = index >= 0 && index < lessons.length - 1 ? lessons[index + 1] : undefined;
  return (
    <div className="grid gap-4 sm:grid-cols-2">
      {previous !== undefined ? (
        <Link className="rounded-lg border bg-surface-container p-4 transition hover:border-primary/40 focus:outline-none focus:ring-2 focus:ring-primary/60" to={`/tutorials/${areaSlug}/${previous.id}`}>
          <p className="eyebrow">Previous lesson</p>
          <p className="mt-2 flex items-center gap-2 text-sm font-semibold text-on-surface">
            <ArrowLeft size={15} className="shrink-0 text-primary" /> {previous.title}
          </p>
        </Link>
      ) : (
        <div className="rounded-lg border border-dashed p-4">
          <p className="eyebrow">Previous lesson</p>
          <p className="mt-2 text-sm text-on-surface-variant">You are at the start of this area.</p>
        </div>
      )}
      {next !== undefined ? (
        <Link className="rounded-lg border bg-surface-container p-4 text-right transition hover:border-primary/40 focus:outline-none focus:ring-2 focus:ring-primary/60" to={`/tutorials/${areaSlug}/${next.id}`}>
          <p className="eyebrow">Next lesson</p>
          <p className="mt-2 flex items-center justify-end gap-2 text-sm font-semibold text-on-surface">
            {next.title} <ArrowRight size={15} className="shrink-0 text-primary" />
          </p>
        </Link>
      ) : (
        <div className="rounded-lg border border-dashed p-4 text-right">
          <p className="eyebrow">Next lesson</p>
          <p className="mt-2 text-sm text-on-surface-variant">This is the last lesson in this area.</p>
        </div>
      )}
    </div>
  );
}