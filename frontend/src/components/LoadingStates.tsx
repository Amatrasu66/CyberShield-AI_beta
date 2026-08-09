export interface LoadingStatesProps { readonly rows?: number; }
export function LoadingStates({ rows = 3 }: LoadingStatesProps) { return <div className="panel space-y-4 p-5 animate-pulse"><div className="h-4 w-1/3 rounded bg-surface-bright/30" />{Array.from({ length: rows }, (_, index) => <div className="h-10 rounded bg-surface-bright/20" key={index} />)}</div>; }
