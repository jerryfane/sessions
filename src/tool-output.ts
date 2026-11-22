import { asJsonObject, asJsonString, tryParse, type JsonValue } from './extract-util';

/**
 * EXPERIMENT (exp/index-variants): extra message_fts rows for pi transcripts, chosen
 * by env so one build can measure every variant on the same corpus:
 *
 *   SESSIONS_EXP_TOOL_OUTPUT  unset/0   no tool output (upstream behaviour)
 *                             <n>       every tool result, cut to n chars
 *                             commands  only bash results of SELECTED_COMMANDS, cut to 4096
 *   SESSIONS_EXP_COMPACTION=1           compaction summaries, cut to COMPACTION_CAP
 *
 * A row is indexed under the msg_index of the turn it belongs to, so a hit opens there.
 */

export interface ExtraRowOptions {
  /** Characters kept per tool result; 0 = no tool output. */
  cap: number;
  /** Only bash results whose command matches; null = every tool. */
  commands: RegExp | null;
  compaction: boolean;
}

export const SELECTED_COMMANDS = /(^|[;&|(]\s*|\s)(gitmoot\s+message\s+show|gh\s|systemctl\s|curl\s)/;
const COMPACTION_CAP = 8192;
/** Base64/hex-like runs: binary payloads, never search terms. Hashes and ids stay. */
const BLOB = /[A-Za-z0-9+/=_-]{120,}/g;
/** Tool calls awaiting their result, kept across refreshes (bounded). */
const MAX_PENDING = 200;

export function extraRowOptionsFromEnv(): ExtraRowOptions | null {
  const tool = (process.env.SESSIONS_EXP_TOOL_OUTPUT ?? '').trim();
  const compaction = process.env.SESSIONS_EXP_COMPACTION === '1';
  let cap = 0;
  let commands: RegExp | null = null;
  if (tool === 'commands') {
    cap = 4096;
    commands = SELECTED_COMMANDS;
  } else if (/^\d+$/.test(tool)) {
    cap = Number(tool);
  }
  return cap > 0 || compaction ? { cap, commands, compaction } : null;
}

export interface ExtraRow {
  role: 'tool' | 'summary';
  text: string;
}

function resultText(content: JsonValue | undefined): string {
  const s = asJsonString(content);
  if (s !== undefined) return s;
  if (!Array.isArray(content)) return '';
  const parts: string[] = [];
  for (const c of content) {
    const block = asJsonObject(c);
    const text = block?.type === 'text' ? asJsonString(block.text) : undefined;
    if (text) parts.push(text);
  }
  return parts.join('\n');
}

function clean(text: string, cap: number): string {
  return text
    .replace(BLOB, ' ')
    .replace(/[ \t]+/g, ' ')
    .trim()
    .slice(0, cap);
}

/** Pending tool calls: call id → label (the bash command, else the tool name). */
export type PendingCalls = Record<string, string>;

export function createExtraRowStream(opts: ExtraRowOptions, seed: PendingCalls = {}) {
  const pending = new Map(Object.entries(seed));
  const add = (lines: string[], emit: (row: ExtraRow, lineIndex: number) => void): void => {
    for (let li = 0; li < lines.length; li++) {
      const d = tryParse(lines[li]!);
      if (!d) continue;
      if (d.type === 'compaction') {
        const summary = asJsonString(d.summary);
        if (opts.compaction && summary?.trim()) emit({ role: 'summary', text: clean(summary, COMPACTION_CAP) }, li);
        continue;
      }
      if (d.type !== 'message' || opts.cap === 0) continue;
      const msg = asJsonObject(d.message);
      if (!msg) continue;
      if (msg.role === 'assistant' && Array.isArray(msg.content)) {
        for (const c of msg.content) {
          const b = asJsonObject(c);
          const id = asJsonString(b?.id);
          if (!b || b.type !== 'toolCall' || !id) continue;
          const name = asJsonString(b.name) ?? 'tool';
          const command = name === 'bash' ? asJsonString(asJsonObject(b.arguments)?.command) : undefined;
          pending.set(id, command ?? name);
          if (pending.size > MAX_PENDING) pending.delete(pending.keys().next().value!);
        }
        continue;
      }
      let label: string | undefined;
      let output = '';
      let isBash = false;
      if (msg.role === 'toolResult') {
        const id = asJsonString(msg.toolCallId) ?? '';
        const toolName = asJsonString(msg.toolName) ?? 'tool';
        label = pending.get(id) ?? toolName;
        pending.delete(id);
        isBash = toolName === 'bash';
        output = resultText(msg.content);
      } else if (msg.role === 'bashExecution') {
        label = asJsonString(msg.command) ?? 'bash';
        isBash = true;
        output = asJsonString(msg.output) ?? '';
      } else {
        continue;
      }
      if (opts.commands && !(isBash && opts.commands.test(label))) continue;
      const text = clean(output, opts.cap);
      if (text) emit({ role: 'tool', text: `${label.slice(0, 300)}\n${text}` }, li);
    }
  };
  return { add, state: (): PendingCalls => Object.fromEntries(pending) };
}
