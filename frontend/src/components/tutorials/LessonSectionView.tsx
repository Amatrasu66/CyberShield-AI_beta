import { AlertTriangle, CheckCircle2, Info, ShieldAlert } from 'lucide-react';
import type { CalloutTone, TutorialSection } from '../../types/tutorials';
import { Badge } from '../ui';

const calloutStyles: Readonly<Record<CalloutTone, { readonly className: string; readonly icon: typeof Info }>> = {
  success: { className: 'border-success/30 bg-success/5 text-success', icon: CheckCircle2 },
  warning: { className: 'border-warning/30 bg-warning/5 text-warning', icon: ShieldAlert },
  danger: { className: 'border-danger/30 bg-danger/5 text-danger', icon: AlertTriangle },
  primary: { className: 'border-primary/30 bg-primary/5 text-primary', icon: Info },
};

export interface LessonSectionViewProps { readonly section: TutorialSection; }

export function LessonSectionView({ section }: LessonSectionViewProps) {
  if (section.kind === 'text') {
    return (
      <div>
        <h2 className="font-display text-lg font-semibold text-on-surface">{section.title}</h2>
        <p className="mt-2 text-sm leading-6 text-on-surface-variant">{section.body}</p>
      </div>
    );
  }

  if (section.kind === 'list') {
    return (
      <div>
        <h2 className="font-display text-lg font-semibold text-on-surface">{section.title}</h2>
        {section.intro !== undefined && <p className="mt-2 text-sm leading-6 text-on-surface-variant">{section.intro}</p>}
        <ul className="mt-4 space-y-3">
          {section.items.map((item) => (
            <li className="flex items-start gap-3 text-sm leading-6 text-on-surface-variant" key={item}>
              <span className="mt-2 h-1.5 w-1.5 shrink-0 rounded-full bg-primary" />
              <span>{item}</span>
            </li>
          ))}
        </ul>
      </div>
    );
  }

  if (section.kind === 'callout') {
    const callout = calloutStyles[section.tone];
    const CalloutIcon = callout.icon;
    return (
      <div className={`rounded-lg border p-4 ${callout.className}`}>
        <div className="flex items-start gap-3">
          <CalloutIcon className="mt-0.5 shrink-0" size={18} />
          <div>
            {section.title !== undefined && <p className="text-sm font-semibold">{section.title}</p>}
            <p className="mt-1 text-sm leading-6 text-on-surface-variant">{section.body}</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div>
      <div className="flex items-center justify-between gap-3">
        <h2 className="font-display text-lg font-semibold text-on-surface">{section.title}</h2>
        <Badge tone="primary">Example</Badge>
      </div>
      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <div>
          <p className="eyebrow mb-1">{section.inputLabel}</p>
          <pre className="break-words whitespace-pre-wrap rounded border bg-surface-low p-3 font-mono text-xs leading-5 text-on-surface">{section.input}</pre>
        </div>
        <div>
          <p className="eyebrow mb-1">{section.outputLabel}</p>
          <pre className="break-words whitespace-pre-wrap rounded border bg-surface-low p-3 font-mono text-xs leading-5 text-on-surface">{section.output}</pre>
        </div>
      </div>
      {section.detail !== undefined && <p className="mt-3 text-xs leading-5 text-on-surface-variant">{section.detail}</p>}
    </div>
  );
}