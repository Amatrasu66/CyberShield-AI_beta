import type { LucideIcon } from 'lucide-react';

export type TutorialStatus = 'ready' | 'planned';

export type CalloutTone = 'success' | 'warning' | 'danger' | 'primary';

export interface TutorialTextSection {
  readonly kind: 'text';
  readonly title: string;
  readonly body: string;
}

export interface TutorialListSection {
  readonly kind: 'list';
  readonly title: string;
  readonly intro?: string;
  readonly items: readonly string[];
}

export interface TutorialCalloutSection {
  readonly kind: 'callout';
  readonly title?: string;
  readonly tone: CalloutTone;
  readonly body: string;
}

export interface TutorialExampleSection {
  readonly kind: 'example';
  readonly title: string;
  readonly inputLabel: string;
  readonly input: string;
  readonly outputLabel: string;
  readonly output: string;
  readonly detail?: string;
}

export type TutorialSection =
  | TutorialTextSection
  | TutorialListSection
  | TutorialCalloutSection
  | TutorialExampleSection;

export interface TutorialLesson {
  readonly id: string;
  readonly title: string;
  readonly summary: string;
  readonly readMinutes: number;
  readonly sections: readonly TutorialSection[];
  readonly related?: readonly { readonly label: string; readonly to: string }[];
}

export interface TutorialArea {
  readonly slug: string;
  readonly title: string;
  readonly eyebrow: string;
  readonly description: string;
  readonly icon: LucideIcon;
  readonly toolLabel: string;
  readonly toolPath: string | null;
  readonly status: TutorialStatus;
  readonly lessons: readonly TutorialLesson[];
}