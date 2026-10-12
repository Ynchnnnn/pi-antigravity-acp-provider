import { execFileSync } from "node:child_process";
import os from "node:os";
import path from "node:path";

import { inspectAntigravityAuth, resolveAntigravityAcpDirectory } from "./antigravity.js";

/** Selects the Antigravity ACP server's secure-file credential backend
 * (`credential_store.py`: `AGY_ACP_FORCE_FILE_STORAGE`). */
export const FORCE_FILE_STORAGE_ENV = "AGY_ACP_FORCE_FILE_STORAGE";

/** macOS keychain coordinates of the server's consumer (CCPA) credential:
 * `credential_store.KEYCHAIN_SERVICE` and the consumer `_KEYCHAIN_ACCOUNT`. */
export const KEYCHAIN_SERVICE = "gemini";
export const KEYCHAIN_ACCOUNT = "antigravity-acp";

const SECURITY_CLI = "/usr/bin/security";
const KEYCHAIN_LOOKUP_TIMEOUT_MS = 3_000;

export type CredentialStorageReason =
	| "explicit-override"
	| "not-darwin"
	| "no-refreshable-token-file"
	| "keychain-entry-present"
	| "missing-keychain-entry";

export interface CredentialStorageDecision {
	/** Child environment entries to apply; empty when the server default is safe. */
	env: Record<string, string>;
	reason: CredentialStorageReason;
}

export interface CredentialStorageOptions {
	env?: NodeJS.ProcessEnv;
	platform?: NodeJS.Platform;
	tokenPath?: string;
	/** Injectable keychain probe for tests; returns whether the entry exists. */
	keychainEntry?: (service: string, account: string) => boolean;
}

function defaultKeychainLookup(service: string, account: string): boolean {
	try {
		execFileSync(SECURITY_CLI, ["find-generic-password", "-s", service, "-a", account], {
			timeout: KEYCHAIN_LOOKUP_TIMEOUT_MS,
			stdio: "ignore",
		});
		return true;
	} catch {
		// Absent, locked, or denied: treat the entry as unavailable.
		return false;
	}
}

/** The server prefers the login keychain on macOS and falls back to the secure
 * file only when that keychain is unusable. A plaintext token file that the
 * keychain does not mirror is therefore invisible to the server: every new
 * server process reports "Credentials missing or invalid", runs interactive
 * Google consent, and can exceed the session-setup deadline. Pin the server to
 * the backend this provider inspects only in that specific mismatch. */
export function resolveCredentialStorageDecision(
	options: CredentialStorageOptions = {},
): CredentialStorageDecision {
	const env = options.env ?? process.env;
	if (env[FORCE_FILE_STORAGE_ENV]?.trim()) return { env: {}, reason: "explicit-override" };

	const platform = options.platform ?? process.platform;
	if (platform !== "darwin") return { env: {}, reason: "not-darwin" };

	const tokenPath = options.tokenPath ?? path.join(resolveAntigravityAcpDirectory(), "acp_token.json");
	if (inspectAntigravityAuth(path.dirname(tokenPath)).status !== "oauth-refreshable") {
		return { env: {}, reason: "no-refreshable-token-file" };
	}

	const lookup = options.keychainEntry ?? defaultKeychainLookup;
	if (lookup(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT)) return { env: {}, reason: "keychain-entry-present" };

	return {
		env: { [FORCE_FILE_STORAGE_ENV]: "1" },
		reason: "missing-keychain-entry",
	};
}

/** Applies the decision without mutating `baseEnv`, mirroring the other
 * child-only environment adapters. */
export function applyCredentialStorageEnvironment(
	baseEnv: NodeJS.ProcessEnv = process.env,
	options: Omit<CredentialStorageOptions, "env"> = {},
): NodeJS.ProcessEnv {
	const decision = resolveCredentialStorageDecision({
		...options,
		env: baseEnv,
		tokenPath:
			options.tokenPath ?? path.join(resolveAntigravityAcpDirectory(), "acp_token.json"),
	});
	return { ...baseEnv, ...decision.env };
}

/** Human-readable backend state for `doctor`/`status` diagnostics. */
export function describeCredentialStorage(): string {
	const decision = resolveCredentialStorageDecision();
	switch (decision.reason) {
		case "missing-keychain-entry":
			return `secure file (macOS keychain entry ${KEYCHAIN_SERVICE}/${KEYCHAIN_ACCOUNT} is absent; the server requested interactive login per process)`;
		case "keychain-entry-present":
			return `macOS keychain (${KEYCHAIN_SERVICE}/${KEYCHAIN_ACCOUNT})`;
		case "explicit-override":
			return `${FORCE_FILE_STORAGE_ENV} set by the user`;
		case "no-refreshable-token-file":
			return "server default (no refreshable token file to reuse)";
		default:
			return "server default (secure file)";
	}
}
