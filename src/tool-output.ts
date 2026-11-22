import { asJsonObject, asJsonString, tryParse, type JsonValue } from './extract-util';
import { redactSecrets, type RedactionCounts } from './redact';

/**
 * Tool output as searchable rows, for pi transcripts. A fact often exists only in what a
 * command printed (a version, a size, a PR state), which message text never repeats.
 * Each tool result becomes one row: the call (the bash command, else the tool name),
 * then the start of its output. Secrets are redacted before anything is kept.
 */

/** Output characters kept per tool result. */
export const TOOL_OUTPUT_CHARS = 1024;
/** Characters of the call kept as the row's first line. */
const LABEL_CHARS = 300;
/** Output is redacted over this prefix before the final cut, so a secret that straddles
 *  the cut is redacted whole rather than kept as a fragment too short to recognise. */
const REDACT_WINDOW = 4 * TOOL_OUTPUT_CHARS;
/** Base64/hex-like runs: binary payloads, never search terms. Ids and hashes stay. */
const BLOB = /[A-Za-z0-9+/=_-]{120,}/g;
/** Tool calls awaiting their result, kept across refreshes; bounded against calls whose
 *  result never arrives (an aborted turn). */
const MAX_PENDING = 200;

/** Pending tool calls: call id → label. */
export type PendingCalls = Record<string, string>;

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

function toolRow(label: string, output: string, counts: RedactionCounts): string {
  const head = redactSecrets(label.slice(0, LABEL_CHARS), counts);
  const body = redactSecrets(output.slice(0, REDACT_WINDOW), counts)
    .replace(BLOB, ' ')
    .replace(/[ \t]+/g, ' ')
    .trim()
    .slice(0, TOOL_OUTPUT_CHARS);
  return body ? `${head}\n${body}` : '';
}

/**
 * Tool rows from pi transcript lines, fed in file order (resumable from `pending`).
 * `emit` receives each row's text and the index of the line that produced it.
 */
export function createToolOutputStream(pending: PendingCalls = {}) {
  const calls = new Map(Object.entries(pending));
  const counts: RedactionCounts = {};
  const add = (lines: string[], emit: (text: string, lineIndex: number) => void): void => {
    for (let li = 0; li < lines.length; li++) {
      const d = tryParse(lines[li]!);
      const msg = d?.type === 'message' ? asJsonObject(d.message) : undefined;
      if (!msg) continue;
      if (msg.role === 'assistant' && Array.isArray(msg.content)) {
        for (const c of msg.content) {
          const block = asJsonObject(c);
          const id = asJsonString(block?.id);
          if (!block || block.type !== 'toolCall' || !id) continue;
          const name = asJsonString(block.name) ?? 'tool';
          const command = name === 'bash' ? asJsonString(asJsonObject(block.arguments)?.command) : undefined;
          calls.set(id, command ?? name);
          if (calls.size > MAX_PENDING) calls.delete(calls.keys().next().value!);
        }
      } else if (msg.role === 'toolResult') {
        const id = asJsonString(msg.toolCallId) ?? '';
        const label = calls.get(id) ?? asJsonString(msg.toolName) ?? 'tool';
        calls.delete(id);
        const text = toolRow(label, resultText(msg.content), counts);
        if (text) emit(text, li);
      } else if (msg.role === 'bashExecution') {
        const text = toolRow(asJsonString(msg.command) ?? 'bash', asJsonString(msg.output) ?? '', counts);
        if (text) emit(text, li);
      }
    }
  };
  return {
    add,
    /** Calls still awaiting their result, for the saved state. */
    pending: (): PendingCalls => Object.fromEntries(calls),
    /** Secrets redacted so far, by kind. */
    redactions: (): RedactionCounts => counts,
  };
}
