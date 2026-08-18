import { ArrowLeft } from 'lucide-react';
import { Link } from 'react-router-dom';

export interface TutorialNotFoundProps { readonly message: string; }

export function TutorialNotFound({ message }: TutorialNotFoundProps) {
  return (
    <div className="flex min-h-[60vh] items-center justify-center">
      <div className="max-w-lg text-center">
        <p className="font-mono text-6xl font-bold text-primary/30">404</p>
        <h1 className="mt-4 font-display text-3xl font-bold text-on-surface">Tutorial not found</h1>
        <p className="mt-3 text-on-surface-variant">{message}</p>
        <Link className="mt-6 inline-flex h-10 items-center justify-center gap-2 rounded bg-primary px-4 text-sm font-semibold text-primary-foreground transition hover:brightness-110 focus:outline-none focus:ring-2 focus:ring-primary/60" to="/tutorials">
          <ArrowLeft size={16} /> Back to tutorials
        </Link>
      </div>
    </div>
  );
}