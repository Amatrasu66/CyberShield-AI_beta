import type { ReactNode } from 'react';

export interface PageHeaderProps { readonly eyebrow: string; readonly title: string; readonly description: string; readonly actions?: ReactNode; }
export function PageHeader({ eyebrow, title, description, actions }: PageHeaderProps) { return <div className="mb-7 flex flex-col justify-between gap-5 md:flex-row md:items-end"><div><p className="eyebrow mb-2">{eyebrow}</p><h1 className="font-display text-3xl font-bold tracking-tight text-on-surface md:text-4xl">{title}</h1><p className="mt-2 max-w-2xl text-sm leading-6 text-on-surface-variant">{description}</p></div>{actions && <div className="flex shrink-0 gap-2">{actions}</div>}</div>; }
