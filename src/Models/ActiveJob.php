<?php
/**
 * Tracks which scan job the admin page is currently attached to.
 *
 * @package Integrum\SecurityScanner\Models
 */

declare( strict_types = 1 );

namespace Integrum\SecurityScanner\Models;

/**
 * Wraps the active-job transient and its rate-limit marker.
 *
 * The pointer has to outlive the 1-hour per-job state TTL while the page
 * keeps polling, but rewriting it on every 4-second poll would hammer the
 * options table, so refreshes are gated by a short-lived marker transient.
 */
final class ActiveJob {

	/**
	 * Transient holding the current job id.
	 */
	private const KEY = 'integrum_security_scanner_active_job';

	/**
	 * Marker transient that gates TTL refreshes.
	 */
	private const TOUCH_KEY = 'integrum_security_scanner_active_job_touch';

	/**
	 * How often the pointer may be re-armed.
	 */
	private const TOUCH_INTERVAL = 30 * MINUTE_IN_SECONDS;

	/**
	 * Pointer lifetime.
	 */
	private const TTL = HOUR_IN_SECONDS;

	/**
	 * Stores the job id and drops any stale refresh marker.
	 *
	 * @param string $job_id Scan job id.
	 */
	public function start( string $job_id ): void {
		set_transient( self::KEY, $job_id, self::TTL );
		delete_transient( self::TOUCH_KEY );
	}

	/**
	 * Returns the active job id, or an empty string when there is none.
	 */
	public function get(): string {
		$job_id = get_transient( self::KEY );
		return is_string( $job_id ) ? $job_id : '';
	}

	/**
	 * Re-arms the pointer TTL, rate-limited to once per TOUCH_INTERVAL.
	 *
	 * @param string $job_id Scan job id.
	 */
	public function touch( string $job_id ): void {
		if ( false !== get_transient( self::TOUCH_KEY ) ) {
			return;
		}
		set_transient( self::TOUCH_KEY, 1, self::TOUCH_INTERVAL );
		set_transient( self::KEY, $job_id, self::TTL );
	}

	/**
	 * Forgets the active job and its marker.
	 */
	public function clear(): void {
		delete_transient( self::KEY );
		delete_transient( self::TOUCH_KEY );
	}
}
