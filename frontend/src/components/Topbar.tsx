import { Bell, Menu, Search } from 'lucide-react';
import { Button } from './ui';

export interface TopbarProps { readonly onMenu: () => void; }
export function Topbar({ onMenu }: TopbarProps) { return <header className="flex h-16 items-center justify-between border-b bg-background/85 px-4 backdrop-blur lg:px-8"><Button variant="ghost" className="lg:hidden" aria-label="Open navigation" onClick={onMenu}><Menu size={20} /></Button><div className="hidden items-center gap-2 text-sm text-on-surface-variant md:flex"><Search size={17} /><span>Search scans, reports, and assets</span></div><div className="flex items-center gap-3"><span className="hidden font-mono text-xs text-success sm:block">● Systems operational</span><Button variant="ghost" className="w-10 px-0" aria-label="Notifications"><Bell size={19} /></Button></div></header>; }
