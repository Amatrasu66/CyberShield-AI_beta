import { useState, type ReactNode } from 'react';
import { Sidebar } from './Sidebar';
import { Topbar } from './Topbar';

export interface AppShellProps { readonly children: ReactNode; }
export function AppShell({ children }: AppShellProps) { const [open, setOpen] = useState(false); return <div className="min-h-screen bg-background lg:flex"><Sidebar open={open} onNavigate={() => setOpen(false)} /><div className="min-w-0 flex-1"><Topbar onMenu={() => setOpen(true)} /><main className="grid-glow min-h-[calc(100vh-4rem)] px-4 py-7 md:px-8 lg:px-10">{children}</main></div>{open && <button className="fixed inset-0 z-30 bg-black/60 lg:hidden" aria-label="Close navigation" onClick={() => setOpen(false)} />}</div>; }
