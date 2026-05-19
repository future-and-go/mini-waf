import type { ConditionNode, Condition, ConditionField } from "../types/api";
import { MAX_TREE_DEPTH, MAX_TREE_LEAVES } from "../types/api";

// ── Type guards ───────────────────────────────────────────────────────────────

export function isLeaf(node: ConditionNode): node is Condition {
  return "field" in node;
}

export function isAnd(node: ConditionNode): node is { and: ConditionNode[] } {
  return "and" in node;
}

export function isOr(node: ConditionNode): node is { or: ConditionNode[] } {
  return "or" in node;
}

export function isNot(node: ConditionNode): node is { not: ConditionNode } {
  return "not" in node;
}

// ── Field label helpers ───────────────────────────────────────────────────────

export function compileFieldLabel(f: ConditionField): string {
  if (typeof f === "string") return f;
  if ("header" in f) return `header.${f.header}`;
  if ("cookie" in f) return f.cookie === null ? "cookie" : `cookie.${f.cookie}`;
  return String(f);
}

export function parseFieldLabel(label: string): ConditionField {
  if (label.startsWith("header.")) {
    const name = label.slice("header.".length);
    if (!name) throw new Error(`Invalid header field: ${label}`);
    return { header: name };
  }
  if (label === "cookie") return { cookie: null };
  if (label.startsWith("cookie.")) {
    return { cookie: label.slice("cookie.".length) };
  }
  return label as ConditionField;
}

// ── Tree metrics ──────────────────────────────────────────────────────────────

function treeMetrics(node: ConditionNode, depth = 0): { maxDepth: number; leaves: number } {
  if (isLeaf(node)) return { maxDepth: depth, leaves: 1 };
  if (isNot(node)) {
    const r = treeMetrics(node.not, depth + 1);
    return { maxDepth: r.maxDepth, leaves: r.leaves };
  }
  const children = isAnd(node) ? node.and : (node as { or: ConditionNode[] }).or;
  let maxDepth = depth;
  let leaves = 0;
  for (const child of children) {
    const r = treeMetrics(child, depth + 1);
    if (r.maxDepth > maxDepth) maxDepth = r.maxDepth;
    leaves += r.leaves;
  }
  return { maxDepth, leaves };
}

export function validateTree(
  node: ConditionNode,
): { ok: true } | { ok: false; error: string; max: number } {
  const { maxDepth, leaves } = treeMetrics(node);
  if (maxDepth > MAX_TREE_DEPTH) return { ok: false, error: "treeDepthExceeded", max: MAX_TREE_DEPTH };
  if (leaves > MAX_TREE_LEAVES) return { ok: false, error: "treeLeavesExceeded", max: MAX_TREE_LEAVES };
  return { ok: true };
}

// ── Leaf validation (client-side only; authoritative check is server-side) ───

export function validateLeaf(c: Condition): { ok: true } | { ok: false; error: string } {
  if (c.operator === "regex") {
    try {
      new RegExp(String(c.value));
    } catch {
      return { ok: false, error: "invalidRegex" };
    }
  }
  if (c.operator === "cidr_match") {
    const cidrRe = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$|^[0-9a-fA-F:]+\/\d{1,3}$/;
    if (!cidrRe.test(String(c.value))) return { ok: false, error: "invalidCidr" };
  }
  return { ok: true };
}

// ── Immutable tree helpers ────────────────────────────────────────────────────

export function cloneTree(node: ConditionNode): ConditionNode {
  return JSON.parse(JSON.stringify(node)) as ConditionNode;
}

// ── Basic ConditionNode shape check (for JSON editor) ─────────────────────────
// Returns true if the parsed value looks like a valid ConditionNode.
export function isConditionNodeShape(v: unknown): v is ConditionNode {
  if (!v || typeof v !== "object") return false;
  const o = v as Record<string, unknown>;
  if ("and" in o) return Array.isArray(o.and);
  if ("or" in o) return Array.isArray(o.or);
  if ("not" in o) return typeof o.not === "object" && o.not !== null;
  // leaf
  return "field" in o && "operator" in o && "value" in o;
}
