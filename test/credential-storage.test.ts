import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
	applyCredentialStorageEnvironment,
	FORCE_FILE_STORAGE_ENV,
	KEYCHAIN_ACCOUNT,
	KEYCHAIN_SERVICE,
	resolveCredentialStorageDecision,
} from "../src/acp/credential-storage.js";

const roots: string[] = [];
afterEach(() => {
	for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
});

function tokenPathWith(content: string | undefined): string {
	const root = fs.mkdtempSync(path.join(os.tmpdir(), "antigravity-storage-"));
	roots.push(root);
	const tokenPath = path.join(root, "acp_token.json");
	if (content !== undefined) fs.writeFileSync(tokenPath, content);
	return tokenPath;
}

const refreshable = '{"refresh_token":"fixture","client_id":"fixture"}';

describe("macOS credential storage selection", () => {
	it("pins the server to the secure file when the keychain entry is absent", () => {
		const lookup = vi.fn(() => false);
		const decision = resolveCredentialStorageDecision({
			env: {},
			platform: "darwin",
			tokenPath: tokenPathWith(refreshable),
			keychainEntry: lookup,
		});
		expect(decision.env).toEqual({ [FORCE_FILE_STORAGE_ENV]: "1" });
		expect(decision.reason).toBe("missing-keychain-entry");
		expect(lookup).toHaveBeenCalledWith(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT);
	});

	it("leaves a populated keychain authoritative", () => {
		const decision = resolveCredentialStorageDecision({
			env: {},
			platform: "darwin",
			tokenPath: tokenPathWith(refreshable),
			keychainEntry: () => true,
		});
		expect(decision.env).toEqual({});
		expect(decision.reason).toBe("keychain-entry-present");
	});

	it("never probes the keychain without a refreshable token file to reuse", () => {
		for (const content of [undefined, "not-json", '{"refresh_token":""}', '{"client_id":"fixture"}']) {
			const lookup = vi.fn(() => false);
			const decision = resolveCredentialStorageDecision({
				env: {},
				platform: "darwin",
				tokenPath: tokenPathWith(content),
				keychainEntry: lookup,
			});
			expect(decision.env).toEqual({});
			expect(decision.reason).toBe("no-refreshable-token-file");
			expect(lookup).not.toHaveBeenCalled();
		}
	});

	it("keeps the platform default outside macOS", () => {
		const lookup = vi.fn(() => false);
		const decision = resolveCredentialStorageDecision({
			env: {},
			platform: "linux",
			tokenPath: tokenPathWith(refreshable),
			keychainEntry: lookup,
		});
		expect(decision).toEqual({ env: {}, reason: "not-darwin" });
		expect(lookup).not.toHaveBeenCalled();
	});

	it("honors an explicit user override", () => {
		const lookup = vi.fn(() => false);
		for (const value of ["1", "true"]) {
			const decision = resolveCredentialStorageDecision({
				env: { [FORCE_FILE_STORAGE_ENV]: value },
				platform: "darwin",
				tokenPath: tokenPathWith(refreshable),
				keychainEntry: lookup,
			});
			expect(decision).toEqual({ env: {}, reason: "explicit-override" });
		}
		expect(lookup).not.toHaveBeenCalled();
	});

	it("applies the decision without mutating the inherited environment", () => {
		const source: NodeJS.ProcessEnv = { GEMINI_API_KEY: "fixture", PATH: "/usr/bin" };
		const result = applyCredentialStorageEnvironment(source, {
			platform: "darwin",
			tokenPath: tokenPathWith(refreshable),
			keychainEntry: () => false,
		});
		expect(result[FORCE_FILE_STORAGE_ENV]).toBe("1");
		expect(result.PATH).toBe("/usr/bin");
		expect(source[FORCE_FILE_STORAGE_ENV]).toBeUndefined();
	});
});
