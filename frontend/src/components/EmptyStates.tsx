import { FileSearch } from 'lucide-react';
import { Button } from './ui';

export interface EmptyStatesProps { readonly title?: string; readonly description?: string; }
export function EmptyStates({ title = 'No reports generated', description = 'Start a demo scan to create a report that appears here.' }: EmptyStatesProps) { return <div className="panel flex flex-col items-center justify-center p-10 text-center"><span className="mb-4 grid h-14 w-14 place-items-center rounded-full bg-primary/10 text-primary"><FileSearch /></span><h2 className="font-display text-lg font-semibold">{title}</h2><p className="mt-2 max-w-sm text-sm text-on-surface-variant">{description}</p><Button className="mt-5">Start a scan</Button></div>; }
