import type { SimpleWebAuthnLogger } from '../../helpers/logging.ts';

export enum SERVICE_STATE {
  DISABLED = 'DISABLED',
  REFRESHING = 'REFRESHING',
  READY = 'READY',
}

export class ServiceStateTracker {
  private state = SERVICE_STATE.DISABLED;
  private stateGeneration = 1;

  constructor(
    private readonly name: string,
    private readonly logger: Required<SimpleWebAuthnLogger>,
  ) {}

  /**
   * Get the current state
   */
  get current(): SERVICE_STATE {
    return this.state;
  }

  /**
   * Monotonically increasing generation for the service's current state.
   *
   * Services that hand out something which can be consumed later (challenges, cached metadata,
   * etc.) can stamp that value with the generation in which it was created. After a reset or a
   * state transition that invalidates the previous generation, consumers can compare the stamp to
   * this value before publishing anything.
   */
  get generation(): number {
    return this.stateGeneration;
  }

  /** Alias for `generation` */
  get currentGeneration(): number {
    return this.stateGeneration;
  }

  /**
   * A snapshot of the state and generation that consumers can store alongside a candidate.
   */
  snapshot(): { name: string; state: SERVICE_STATE; generation: number } {
    return {
      name: this.name,
      state: this.state,
      generation: this.stateGeneration,
    };
  }

  /**
   * Advance the service generation, invalidating any candidates stamped with an older value.
   *
   * Returns the new generation so callers can include it in the state they publish.
   */
  advanceGeneration(reason?: string): number {
    this.stateGeneration += 1;

    const reasonSuffix = reason ? `: ${reason}` : '';
    this.logger.debug(
      `${this.name} advanced to generation ${this.stateGeneration}${reasonSuffix}`,
    );

    return this.stateGeneration;
  }

  /**
   * Set a new state and report it
   */
  set(next: SERVICE_STATE) {
    // If we're already in this state then there's nothing to do
    if (this.state === next) {
      return;
    }

    this.state = next;

    this.logger.debug(`${this.name} is ${SERVICE_STATE[this.state]}`);
  }

  /**
   * A helper method to pause execution until the service is ready
   */
  pauseUntilReady(): Promise<void> {
    if (this.state === SERVICE_STATE.READY) {
      return Promise.resolve();
    }

    // State isn't ready, so set up polling
    const readyPromise = new Promise<void>((resolve, reject) => {
      const totalTimeoutMS = 70_000;
      const intervalMS = 100;
      let iterations = totalTimeoutMS / intervalMS;

      // Check service state every `intervalMS` milliseconds
      const intervalID = globalThis.setInterval(() => {
        if (iterations < 1) {
          clearInterval(intervalID);
          reject(`State did not become ready in ${totalTimeoutMS / 1000} seconds`);
        } else if (this.state === SERVICE_STATE.READY) {
          clearInterval(intervalID);
          resolve();
        }

        iterations -= 1;
      }, intervalMS);
    });

    return readyPromise;
  }
}
