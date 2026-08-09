import type { ButtonHTMLAttributes, InputHTMLAttributes, ReactNode } from 'react';
import { cn } from '../utils/cn';

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> { readonly variant?: 'primary' | 'secondary' | 'ghost' | 'danger'; readonly children: ReactNode; }
export function Button({ variant = 'primary', className, children, ...props }: ButtonProps) { const styles = { primary: 'bg-primary text-primary-foreground hover:brightness-110', secondary: 'bg-surface-high text-on-surface hover:bg-surface-bright', ghost: 'bg-transparent text-on-surface-variant hover:bg-surface-high hover:text-on-surface', danger: 'bg-danger/15 text-danger hover:bg-danger/25' }; return <button className={cn('inline-flex h-10 items-center justify-center gap-2 rounded px-4 text-sm font-semibold transition focus:outline-none focus:ring-2 focus:ring-primary/60 disabled:opacity-60', styles[variant], className)} {...props}>{children}</button>; }

export interface CardProps { readonly children: ReactNode; readonly className?: string; }
export function Card({ children, className }: CardProps) { return <section className={cn('panel', className)}>{children}</section>; }

export interface BadgeProps { readonly children: ReactNode; readonly tone?: 'success' | 'warning' | 'danger' | 'primary'; }
export function Badge({ children, tone = 'primary' }: BadgeProps) { const styles = { success: 'bg-success/15 text-success', warning: 'bg-warning/15 text-warning', danger: 'bg-danger/15 text-danger', primary: 'bg-primary/15 text-primary' }; return <span className={cn('inline-flex items-center rounded-full px-2.5 py-1 font-mono text-[11px] font-medium uppercase tracking-wide', styles[tone])}>{children}</span>; }

export interface TextInputProps extends InputHTMLAttributes<HTMLInputElement> { readonly label: string; }
export function TextInput({ label, id, className, ...props }: TextInputProps) { return <label className="grid gap-2 text-sm font-medium text-on-surface"><span>{label}</span><input id={id} className={cn('h-11 rounded border bg-surface-low px-3 text-on-surface placeholder:text-on-surface-variant/60 focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20', className)} {...props} /></label>; }

export interface DataTableProps { readonly headers: readonly string[]; readonly rows: readonly (readonly string[])[]; }
export function DataTable({ headers, rows }: DataTableProps) { return <div className="overflow-x-auto"><table className="w-full min-w-[520px] text-left text-sm"><thead className="border-y bg-surface-low font-mono text-[11px] uppercase tracking-wider text-on-surface-variant"><tr>{headers.map((header) => <th className="px-4 py-3 font-medium" key={header}>{header}</th>)}</tr></thead><tbody>{rows.map((row, index) => <tr className="border-b last:border-0 hover:bg-surface-high/40" key={`${row[0]}-${index}`}>{row.map((value) => <td className="px-4 py-3 text-on-surface-variant first:font-medium first:text-on-surface" key={value}>{value}</td>)}</tr>)}</tbody></table></div>; }
