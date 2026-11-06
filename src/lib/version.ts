import { PACKAGE_RULE_LIST } from "./deps/packages";
import { PATTERN_RULES } from "./engine/rules/patterns";
import { QUALITY_RULES } from "./engine/quality";
import { SECRET_RULES } from "./engine/secrets";
import { SINKS } from "./engine/taint/model";

/** Shared by the CLI, MCP server and web pipeline so the CLI bundle can avoid pulling the LLM swarm. */
export const ENGINE_VERSION = "2.0.0";
export const RULE_COUNT =
  PATTERN_RULES.length +
  SECRET_RULES.length +
  new Set(SINKS.map((s) => s.id)).size +
  Object.keys(QUALITY_RULES).length +
  PACKAGE_RULE_LIST.length;
