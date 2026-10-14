// Espejo de lo que devuelve el motor (Demiurge.Core, JSON camelCase, enums como texto).

export type Level = "Info" | "Revisar" | "Peligroso";
export type Severity = "Info" | "Baja" | "Media" | "Alta" | "Critica" | "Pregunta";
export type Verdict = "Limpio" | "Revisar" | "ProbableInfeccion";

export interface QuestionOption { value: string; label: string; weight: number }
export interface UserQuestion { questionId: string; text: string; options: QuestionOption[] }

export interface EntityScore {
  scoringKey: string;
  kind: string;
  displayName: string;
  path?: string;
  score: number;
  level: Level;
  maxSeverity: Severity;
  criticalOverride: boolean;
  attackIds: string[];
  whatWeFound: string;
  whyItCaughtOurAttention: string[];
  howSerious: string;
  whatToDo: string;
  availableActions: string[];
  pendingQuestion?: UserQuestion;
}

export interface HealthItem { name: string; label: string; value?: string; ok?: boolean | null; text?: string }

export interface Summary {
  scanId: number;
  started: string;
  finished?: string;
  type: string;
  verdict: Verdict;
  verdictText: string;
  disclaimer: string;
  immediate?: string;
  elevatedWarning?: string;
  scoreMax: number;
  health: { level: string; summary: string; items: HealthItem[]; issues: HealthItem[] };
  defender?: {
    available: boolean;
    realTime?: boolean | null;
    otherAv: string[];
    recent: { threat: string; time?: string; paths: string[]; stillPresent: boolean }[];
  };
  counts: { danger: number; review: number; questions: number; processes: number; startup: number; connections: number; extensions: number; software: number };
  findings: EntityScore[];
  collectors: { id: string; name: string; success: boolean; error?: string }[];
  feeds: string;
}

export interface InventoryRow {
  key: string;
  name: string;
  detail?: string;
  path?: string;
  whatIsIt: string;
  isItNormal: string;
  status: "ok" | "info" | "review" | "danger" | "question";
  score: number;
  signer?: string;
  columns: Record<string, string | null>;
}

export interface DiffItem { kind: string; key: string; name: string; change: "added" | "removed"; detail?: string; score: number }
export interface DiffReport { previousScanId?: number; previousScanDate?: string; title: string; summary: string[]; items: DiffItem[] }

export interface ActionRecord { id: string; date: string; type: string; target: string; description: string; reverted: boolean }
export interface ActionResult { success: boolean; message: string; actionId?: string; reversible: boolean }

export interface Finding {
  id: string;
  heuristicId: string;
  heuristicName: string;
  entityKind: string;
  entityName: string;
  weight: number;
  severity: Severity;
  attackIds: string[];
  explanation: string;
  rawData: Record<string, unknown>;
  suppression?: string;
}

export interface EntityDetail {
  score?: EntityScore;
  findings: Finding[];
  binary?: {
    path: string; sha256?: string; size: number; modified?: string;
    signature?: { isSigned: boolean; isValid: boolean; isCatalogSigned: boolean; signer?: string };
    reputation: { source: string; verdict: string; family?: string }[];
    productName?: string; companyName?: string;
  };
  knowledge?: { title: string; what: string; normal: string };
  processTree: string[][];
  persistence: { type: string; location: string; name: string; command?: string }[];
  connections: { protocol: string; remoteAddress?: string; remotePort: number; state: string; tiMatch?: string }[];
  attack: string[];
}

export interface Config {
  onlineHashLookups: boolean;
  defenderScanEnabled: boolean;
  defenderAvailable: boolean;
  virusTotalConfigured: boolean;
  abuseChConfigured: boolean;
  yaraX: { enabled: boolean; path?: string; pinned: boolean; rules?: boolean };
  hollowsHunter: { enabled: boolean; path?: string; pinned: boolean };
  hayabusa: { enabled: boolean; path?: string; pinned: boolean };
}

export interface Progress { stage: string; detail?: string; percent: number }
