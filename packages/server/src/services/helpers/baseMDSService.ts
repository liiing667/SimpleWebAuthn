import { fetch } from '../../helpers/fetch.ts';
import {
  buildLoggerAllMethods,
  DefaultNoopLogger,
  type SimpleWebAuthnLogger,
} from '../../helpers/logging.ts';
import { getInitCacheMessage } from './getInitCacheMessage.ts';
import { MDSCache } from './mdsCache.ts';
import { SERVICE_STATE, ServiceStateTracker } from './serviceStateTracker.ts';

/**
 * Functionality shared by services that download, cache, and refresh metadata from FIDO
 * Alliance-style metadata servers (MDS and Convenience MDS.) Subclasses are responsible for
 * parsing and caching what a server returns.
 */
export abstract class BaseMDSService<MDSDataType> {
  protected readonly metadataCache: MDSCache<MDSDataType> = new MDSCache<MDSDataType>();
  protected state: ServiceStateTracker;
  protected logger: Required<SimpleWebAuthnLogger> = DefaultNoopLogger;

  /**
   * A monotonically increasing identifier for the current "generation" of cached data. It's
   * bumped every time `initialize()` resets the cache so that asynchronous work (e.g. an MDS
   * BLOB refresh that was in flight when the service was re-initialized, such as after a
   * restart) can recognize that it's stale and avoid mutating the cache or flipping service
   * state out from underneath the generation that replaced it.
   */
  private generation = 0;

  /** How many hours to wait to check a server again when it has nothing new to download */
  protected readonly defaultRefreshDelayHours = 24;
  /** How many hours to wait to retry a _failed_ attempt to refresh a server */
  protected readonly defaultRetryDelayHours = 3;
  /** Abort downloads that take longer than this many milliseconds. No limit if left `undefined` */
  protected readonly downloadTimeoutMS = 10_000;

  /**
   * @param serviceName Used in logs, e.g. `"MetadataService"`
   */
  constructor(
    protected readonly serviceName: string,
  ) {
    this.state = new ServiceStateTracker(serviceName, this.logger);
  }

  /**
   * Download from the server at `url` (if it has something newer than serial `no`) and cache the
   * result. Returns the number of entries cached, or `undefined` if nothing was cached (e.g. the
   * server had nothing new, or responded unsuccessfully.)
   */
  protected abstract downloadAndCache(url: string, no: number): Promise<number | undefined>;

  /**
   * Called when refreshing a server throws. Implementations can recover from the error (e.g. by
   * delaying the next refresh) or rethrow it so that lookups depending on the refresh fail.
   */
  protected abstract handleRefreshFailure(url: string, err: unknown): void;

  /**
   * Reset the service and move it to the `REFRESHING` state. Call this at the start of
   * `initialize()`.
   */
  protected beginInitialize(logger: SimpleWebAuthnLogger = DefaultNoopLogger): void {
    // Start a new generation before anything is reset so that refreshes from the previous
    // generation (for example one still in flight when the service is re-initialized after a
    // restart) become no-ops instead of writing into the fresh cache
    this.generation += 1;

    this.metadataCache.reset();
    this.serverRefreshes = {};

    this.logger = buildLoggerAllMethods(logger);
    this.state = new ServiceStateTracker(this.serviceName, this.logger);
    this.state.set(SERVICE_STATE.REFRESHING);
  }

  /**
   * The generation of cached data the service is currently on. Capture it at the start of an
   * asynchronous operation and compare it against `this.generation` before touching the cache or
   * service state, to make sure the operation hasn't been superseded by a re-initialization.
   */
  protected get currentGeneration(): number {
    return this.generation;
  }

  /**
   * Whether the provided generation is still the active one (i.e. the service hasn't been
   * re-initialized since the generation was captured.)
   */
  protected generationIsCurrent(generation: number): boolean {
    return generation === this.generation;
  }

  /**
   * Download and cache from each server. A server is only registered for refreshes once data from
   * it has been cached. One that can't be reached, or that doesn't respond with data, is skipped
   * so it can't cause lookups of other metadata to fail.
   *
   * Returns the number of servers entries were cached from.
   */
  protected async initializeServers(mdsServers?: string[]): Promise<number> {
    let numServers = 0;

    for (const url of mdsServers ?? []) {
      try {
        const entriesAdded = await this.downloadAndCache(url, 0);
        if (entriesAdded !== undefined) {
          numServers += 1;
          this.logger.debug(`Cached ${entriesAdded} metadata entries from "${url}"`);
        }
      } catch (err) {
        // Notify of the error and move on
        this.logger.error(`Could not download data from "${url}":`, err);
      }
    }

    return numServers;
  }

  /**
   * Log how much was cached and report the service as ready. Call this at the end of
   * `initialize()`.
   */
  protected finishInitialize(numLocalFiles?: number, numServers?: number): void {
    const cacheMessage = getInitCacheMessage(
      this.serviceName,
      this.metadataCache.count,
      numLocalFiles,
      numServers,
    );
    this.logger.info(cacheMessage);

    this.state.set(SERVICE_STATE.READY);
  }

  /**
   * Request data from a server, with a query param that can short-circuit the download if the
   * latest version is already cached. `no` is the serial number of the last data cached from this
   * server.
   *
   * Returns `undefined` if the server responded with anything other than data, in which case the
   * next refresh will have been delayed.
   *
   * See https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#sctn-mds-blob-proc-rules
   */
  protected async fetchFromServer(url: string, no: number): Promise<Response | undefined> {
    // Capture the generation so response handling below (which can delay the next refresh) can't
    // mutate a newer generation's cache if a re-initialization happened while the request was
    // in flight
    const generation = this.generation;

    const _url = new URL(url);
    _url.searchParams.set('localCopySerial', String(no));
    const resp = await fetch(_url.toString(), {
      signal: AbortSignal.timeout(this.downloadTimeoutMS),
    });

    // We have the latest data, nothing more to do
    if (resp.status === 304) {
      await resp.body?.cancel();
      this.logger.info(
        `The MDS server at "${_url.toString()}" reported nothing new to download (HTTP 304)`,
      );
      // There's nothing new to download, wait another interval before checking again
      if (this.generationIsCurrent(generation)) {
        this.delayNextRefresh(url, this.defaultRefreshDelayHours);
      }
      return;
    }

    // The FIDO MDS servers aggressively rate-limit so be prepared for that. We'll have to try again
    // later.
    if (resp.status === 429) {
      await resp.body?.cancel();
      this.logger.warn(
        `The MDS server at "${_url.toString()}" rate-limited this request (HTTP 429)`,
      );
      // We checked too soon, wait a bit before checking again
      if (this.generationIsCurrent(generation)) {
        this.delayNextRefresh(url, this.defaultRetryDelayHours);
      }
      return;
    }

    if (!resp.ok) {
      await resp.body?.cancel();
      this.logger.warn(
        `The MDS server at "${_url.toString()}" reported an unsuccessful request (HTTP ${resp.status})`,
      );
      // Likely an HTTP 500 error, but anything not within HTTP 200-299. Wait a bit before trying
      // again
      if (this.generationIsCurrent(generation)) {
        this.delayNextRefresh(url, this.defaultRetryDelayHours);
      }
      return;
    }

    return resp;
  }

  /**
   * Refresh every server whose `nextUpdate` has passed
   */
  protected async refreshStaleServers(): Promise<void> {
    const now = new Date();
    const staleURLs = this.metadataCache.getStaleMDSServerURLs(now);

    await Promise.all(staleURLs.map((url) => this.refreshServer(url)));
  }

  /**
   * In-flight refreshes keyed by server URL. Reassigned on every `initialize()` so refreshes from
   * a dead generation can never remove or observe refreshes belonging to the new generation
   */
  private serverRefreshes: { [url: string]: Promise<void> } = {};

  /**
   * Refresh a single server, subscribing to the refresh already in flight if there is one.
   * Failures are passed to `handleRefreshFailure()`.
   */
  private async refreshServer(url: string): Promise<void> {
    // Bind to the current generation's refresh map; a re-initialization swaps in a fresh map, so
    // stale refreshes clean themselves up without touching the new generation's refreshes
    const refreshes = this.serverRefreshes;
    const inFlight = refreshes[url];
    if (inFlight) {
      await inFlight;
      return;
    }

    // Capture the generation so a re-initialization (e.g. after a restart) starting while this
    // refresh is in flight can leave it a no-op, keeping the new generation's cache and state
    // consistent
    const generation = this.generation;

    this.state.set(SERVICE_STATE.REFRESHING);

    const refresh = (async (): Promise<void> => {
      let refreshError: unknown;
      let refreshFailed = false;
      try {
        const mdsNo = this.metadataCache.getMDSServerDataVersion(url);
        await this.downloadAndCache(url, mdsNo);
      } catch (err) {
        this.logger.error(`Could not download data from "${url}":`, err);

        // A re-initialization superseded this refresh, so its failure belongs to a dead
        // generation and must not be handled against (or delay a refresh within) the new one
        if (!this.generationIsCurrent(generation)) {
          return;
        }

        refreshFailed = true;
        refreshError = err;
        this.handleRefreshFailure(url, err);
      } finally {
        delete refreshes[url];

        // Only report ready once every refresh from this still-current generation has finished
        if (
          this.generationIsCurrent(generation) &&
          Object.keys(refreshes).length === 0
        ) {
          this.state.set(SERVICE_STATE.READY);
        }
      }

      // `handleRefreshFailure()` may have rethrown, in which case preserve fail-closed behavior
      if (refreshFailed) {
        throw refreshError;
      }
    })();

    refreshes[url] = refresh;

    await refresh;
  }

  /**
   * Delay the next refresh attempt of this server by the specified number of hours
   */
  protected delayNextRefresh(url: string, numHours: number): void {
    // Servers that haven't been cached from yet (i.e. still initializing) aren't refreshed so
    // there's no refresh to delay
    if (!this.metadataCache.mdsServerIsRegistered(url)) {
      return;
    }

    this.logger.debug(`Delaying next refresh of "${url}" by ${numHours} hours`);
    const numHoursMS = 1000 * 60 * 60 * numHours;
    this.metadataCache.setMDSServerNextUpdate(url, new Date(Date.now() + numHoursMS));
  }
}
