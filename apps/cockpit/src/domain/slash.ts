/**
 * Steering slash commands. These are the verbs an operator types at the bottom
 * of the cockpit; they compile to either a /steer call (inquiry) or an /action
 * call (state intent). The set is fixed and matches the task contract.
 *
 * Wording follows the rest of the instrument: a stage is a "gate", a work item
 * is a "line", and the allow set holds specialists rather than models.
 */
export interface SlashCommand {
  /** Command token including the leading slash. */
  cmd: string;
  desc: string;
  /** Whether it maps to POST /action (state intent) or /steer (inquiry). */
  channel: "action" | "steer";
  /** Whether it needs a bound node to make sense. */
  needsNode?: boolean;
}

export const SLASH_COMMANDS: SlashCommand[] = [
  { cmd: "/inspect", desc: "Open the evidence behind this gate", channel: "steer", needsNode: true },
  { cmd: "/why", desc: "Explain the current state in a sentence", channel: "steer", needsNode: true },
  { cmd: "/impact", desc: "Show observed / reachable / unknown impact", channel: "steer", needsNode: true },
  { cmd: "/fix", desc: "Open a question about what to change before the next attempt", channel: "action", needsNode: true },
  { cmd: "/run", desc: "Admit and run this gate for the first time", channel: "action", needsNode: true },
  { cmd: "/retry", desc: "Run this gate again with another allowed specialist", channel: "action", needsNode: true },
  { cmd: "/pause", desc: "Pause the line and open a question", channel: "action", needsNode: true },
  { cmd: "/discard", desc: "Stop the line, remain fail-closed", channel: "action", needsNode: false },
  { cmd: "/accept", desc: "Accept once every required gate holds", channel: "action", needsNode: false },
];

export const FREE_STEER: SlashCommand = {
  cmd: "/steer",
  desc: "Send free steering to the selected scope",
  channel: "steer",
  needsNode: false,
};

export interface ParsedSteer {
  /** Matched command, if the input begins with a known slash command. */
  command: SlashCommand | null;
  /** Free-text remainder after the command token. */
  text: string;
  /** Raw leading token (may be a partial like "/ins"). */
  token: string;
}

/**
 * Suggest slash commands for the current input. Returns matches whose command
 * token is a prefix of the typed token (case-insensitive). An empty "/"
 * returns the full set. Non-slash input returns no suggestions.
 */
export function suggestSlash(input: string): SlashCommand[] {
  const trimmed = input.replace(/^\s+/, "");
  if (!trimmed.startsWith("/")) return [];
  const token = trimmed.split(/\s/, 1)[0].toLowerCase();
  // Once there's a space after a complete command, stop suggesting.
  if (/\s/.test(trimmed) && SLASH_COMMANDS.some((c) => c.cmd === token)) return [];
  return SLASH_COMMANDS.filter((c) => c.cmd.startsWith(token));
}

export function parseSteer(input: string): ParsedSteer {
  const trimmed = input.trim();
  if (!trimmed) return { command: null, text: "", token: "" };
  const token = trimmed.split(/\s/, 1)[0];
  const command = SLASH_COMMANDS.find((c) => c.cmd === token.toLowerCase()) ?? null;
  if (command) {
    return { command, text: trimmed.slice(token.length).trim(), token };
  }
  if (!trimmed.startsWith("/")) {
    return { command: FREE_STEER, text: trimmed, token };
  }
  return { command: null, text: trimmed, token };
}
