import { ArrowRight, ArrowUpRight } from 'lucide-react';
import { Link } from 'react-router-dom';
import type { TutorialArea } from '../../types/tutorials';
import { Badge, Card } from '../ui';

export interface AreaCardProps { readonly area: TutorialArea; }

export function AreaCard({ area }: AreaCardProps) {
  const Icon = area.icon;
  const ready = area.status === 'ready';
  return (
    <Card className="group flex flex-col p-5">
      <div className="flex items-start justify-between gap-3">
        <span className="grid h-10 w-10 place-items-center rounded-lg bg-primary/15 text-primary">
          <Icon size={20} />
        </span>
        <Badge tone={ready ? 'primary' : 'warning'}>
          {ready ? `${area.lessons.length} lesson${area.lessons.length === 1 ? '' : 's'}` : 'Planned'}
        </Badge>
      </div>
      <h2 className="mt-4 font-display text-lg font-semibold text-on-surface">{area.title}</h2>
      <p className="mt-1 flex-1 text-sm leading-6 text-on-surface-variant">{area.description}</p>
      <div className="mt-4 flex flex-wrap items-center gap-x-4 gap-y-2">
        <Link className="inline-flex items-center gap-1 rounded text-sm font-semibold text-primary focus:outline-none focus:ring-2 focus:ring-primary/60" to={`/tutorials/${area.slug}`}>
          Open tutorials <ArrowRight className="transition-transform group-hover:translate-x-0.5" size={15} />
        </Link>
        {area.toolPath !== null && (
          <Link className="inline-flex items-center gap-1 rounded text-sm text-on-surface-variant transition hover:text-on-surface focus:outline-none focus:ring-2 focus:ring-primary/60" to={area.toolPath}>
            {area.toolLabel} <ArrowUpRight size={14} />
          </Link>
        )}
      </div>
      {!ready && (
        <p className="mt-3 text-xs leading-5 text-on-surface-variant">
          Reserved for model-backed analysis. It will be documented when the feature is actually implemented.
        </p>
      )}
    </Card>
  );
}