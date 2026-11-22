export interface WebAuthnAbortService {
  /**
   * Prepare an abort signal that will help support multiple auth attempts without needing to
   * reload the page. This is automatically called whenever `startRegistration()` and
   * `startAuthentication()` are called.
   */
  createNewAbortSignal(): AbortSignal;
  /**
   * Start a new ceremony and return both its abort signal and its generation metadata.
   *
   * The generation lets callers carry the same ceremony identity to the server so a result that
   * resolves late cannot be mistaken for the result of a newer ceremony.
   */
  createNewCeremony(): CeremonyAbortState;
  /**
   * Manually cancel any active WebAuthn registration or authentication attempt.
   */
  cancelCeremony(): void;
  /**
   * Check whether the given signal still belongs to the active ceremony.
   */
  isCurrentCeremony(signal: AbortSignal, generation?: number): boolean;
  /** Current ceremony generation for this tab. */
  readonly generation: number;
  /** Alias for `generation`. */
  readonly ceremonyGeneration: number;
  /** Stable identity for this tab's ceremony lineage. */
  readonly ceremonyID: string;
  /** Alias for `ceremonyID`. */
  readonly tabID: string;
  /** Metadata for the signal, if it was created by this service. */
  getCeremonyState(signal: AbortSignal): CeremonyAbortState | undefined;
  /** Whether a generation was cancelled or superseded. */
  isCeremonyCancelled(generation: number): boolean;
}

export type CeremonyAbortState = {
  signal: AbortSignal;
  generation: number;
  ceremonyID: string;
};

type StoredCeremonyState = {
  ceremonyID?: string;
  generation?: number;
  cancelledGenerations?: number[];
};

type StorageLike = {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
};

const TAB_STATE_KEY = 'simplewebauthn:tab-ceremony';
const SHARED_STATE_KEY = 'simplewebauthn:ceremony-generation';

function getStorage(name: 'localStorage' | 'sessionStorage'): StorageLike | undefined {
  try {
    const storage = (globalThis as unknown as Record<string, StorageLike | undefined>)[name];
    if (storage && typeof storage.getItem === 'function') {
      return storage;
    }
  } catch {
    // Storage can be disabled by privacy settings or unavailable in non-browser runtimes.
  }
  return undefined;
}

function readState(storage: StorageLike | undefined, key: string): StoredCeremonyState {
  if (!storage) {
    return {};
  }
  try {
    const raw = storage.getItem(key);
    if (!raw) {
      return {};
    }
    const parsed = JSON.parse(raw) as StoredCeremonyState;
    if (!parsed || typeof parsed !== 'object') {
      return {};
    }
    return {
      ceremonyID: typeof parsed.ceremonyID === 'string' ? parsed.ceremonyID : undefined,
      generation: typeof parsed.generation === 'number' && Number.isFinite(parsed.generation)
        ? parsed.generation
        : undefined,
      cancelledGenerations: Array.isArray(parsed.cancelledGenerations)
        ? parsed.cancelledGenerations.filter((value) =>
          typeof value === 'number' && Number.isFinite(value)
        )
        : undefined,
    };
  } catch {
    return {};
  }
}

function writeState(
  storage: StorageLike | undefined,
  key: string,
  state: StoredCeremonyState,
): void {
  if (!storage) {
    return;
  }
  try {
    storage.setItem(key, JSON.stringify(state));
  } catch {
    // A full or disabled storage must not break the WebAuthn ceremony.
  }
}

function newCeremonyID(): string {
  try {
    const bytes = new Uint8Array(12);
    const crypto = (globalThis as unknown as {
      crypto?: { getRandomValues?: (array: Uint8Array) => Uint8Array };
    }).crypto;
    if (!crypto?.getRandomValues) {
      throw new Error('Web Crypto is not available');
    }
    crypto.getRandomValues(bytes);
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
  } catch {
    return `tab_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 12)}`;
  }
}

export class BaseWebAuthnAbortService implements WebAuthnAbortService {
  private controller: AbortController | undefined;
  private signal: AbortSignal | undefined;
  private _generation = 0;
  private _ceremonyID = newCeremonyID();
  private readonly cancelledGenerations = new Set<number>();
  private readonly signalStates = new WeakMap<AbortSignal, CeremonyAbortState>();

  constructor() {
    const tabState = readState(getStorage('sessionStorage'), TAB_STATE_KEY);
    const sharedState = readState(getStorage('localStorage'), SHARED_STATE_KEY);

    if (tabState.ceremonyID) {
      this._ceremonyID = tabState.ceremonyID;
    }
    this._generation = Math.max(
      this._generation,
      tabState.generation ?? 0,
      sharedState.generation ?? 0,
    );
    for (const generation of [
      ...(tabState.cancelledGenerations ?? []),
      ...(sharedState.cancelledGenerations ?? []),
    ]) {
      this.cancelledGenerations.add(generation);
      this._generation = Math.max(this._generation, generation);
    }
  }

  createNewAbortSignal(): AbortSignal {
    return this.createNewCeremony().signal;
  }

  createNewCeremony(): CeremonyAbortState {
    this.syncSharedGeneration();

    // Abort any existing calls to navigator.credentials.create() or navigator.credentials.get()
    if (this.controller) {
      const abortError = new Error(
        'Cancelling existing WebAuthn API call for new one',
      );
      abortError.name = 'AbortError';
      this.controller.abort(abortError);
    }

    this._generation += 1;
    const newController = new AbortController();
    const state: CeremonyAbortState = {
      signal: newController.signal,
      generation: this._generation,
      ceremonyID: this._ceremonyID,
    };

    this.controller = newController;
    this.signal = newController.signal;
    this.signalStates.set(newController.signal, state);
    try {
      Object.defineProperties(newController.signal, {
        ceremonyGeneration: {
          value: state.generation,
          enumerable: false,
          configurable: true,
        },
        ceremonyID: {
          value: state.ceremonyID,
          enumerable: false,
          configurable: true,
        },
      });
    } catch {
      // AbortSignal is not extensible in every runtime; the WeakMap remains authoritative.
    }
    this.persist();
    return state;
  }

  cancelCeremony(): void {
    this.syncSharedGeneration();

    if (this.controller) {
      const abortError = new Error(
        'Manually cancelling existing WebAuthn API call',
      );
      abortError.name = 'AbortError';
      this.controller.abort(abortError);

      this.controller = undefined;
      this.signal = undefined;
      this.cancelledGenerations.add(this._generation);
      this.persist();
    }
  }

  isCurrentCeremony(signal: AbortSignal, generation?: number): boolean {
    this.syncSharedGeneration();
    const state = this.signalStates.get(signal);
    if (!state) {
      return false;
    }

    return this.signal === signal &&
      !signal.aborted &&
      !this.cancelledGenerations.has(state.generation) &&
      state.generation === this._generation &&
      (generation === undefined || generation === state.generation);
  }

  getCeremonyState(signal: AbortSignal): CeremonyAbortState | undefined {
    return this.signalStates.get(signal);
  }

  isCeremonyCancelled(generation: number): boolean {
    this.syncSharedGeneration();
    return this.cancelledGenerations.has(generation) ||
      generation !== this._generation;
  }

  get generation(): number {
    this.syncSharedGeneration();
    return this._generation;
  }

  get ceremonyGeneration(): number {
    return this.generation;
  }

  get ceremonyID(): string {
    return this._ceremonyID;
  }

  get tabID(): string {
    return this._ceremonyID;
  }

  private syncSharedGeneration(): void {
    const sharedState = readState(getStorage('localStorage'), SHARED_STATE_KEY);
    if (sharedState.generation !== undefined && sharedState.generation > this._generation) {
      this._generation = sharedState.generation;
    }
    for (const generation of sharedState.cancelledGenerations ?? []) {
      this.cancelledGenerations.add(generation);
    }
  }

  private persist(): void {
    const state: StoredCeremonyState = {
      ceremonyID: this._ceremonyID,
      generation: this._generation,
      cancelledGenerations: [...this.cancelledGenerations],
    };
    writeState(getStorage('sessionStorage'), TAB_STATE_KEY, state);
    writeState(getStorage('localStorage'), SHARED_STATE_KEY, {
      generation: this._generation,
      cancelledGenerations: [...this.cancelledGenerations],
    });
  }
}

/**
 * A service singleton to help ensure that only a single WebAuthn ceremony is active at a time.
 *
 * Users of **@simplewebauthn/browser** shouldn't typically need to use this, but it can help e.g.
 * developers building projects that use client-side routing to better control the behavior of
 * their UX in response to router navigation events.
 */
export const WebAuthnAbortService: WebAuthnAbortService = new BaseWebAuthnAbortService();
