<?php
/**
 * JobStore backed by the WP Transients API.
 *
 * Transient key names are identical to the previous inline implementation so
 * in-flight jobs survive the refactor.
 *
 * @package Integrum\SecurityScanner\Models
 */

declare( strict_types = 1 );

namespace Integrum\SecurityScanner\Models;

use Integrum\SecurityScanner\Contracts\JobStoreInterface;

/**
 * Persists per-job scan state through set/get/delete_transient().
 */
final class WpTransientJobStore implements JobStoreInterface {

	/**
	 * Transient name prefix shared by every per-job key.
	 */
	private const PREFIX = 'integrum_security_scanner_';

	/**
	 * Transient lifetime (1 hour) — long enough for a scan to finish, short
	 * enough that abandoned jobs are garbage collected automatically.
	 */
	private const TTL = HOUR_IN_SECONDS;

	/**
	 * Minimum interval between TTL refreshes of the stored payloads.
	 *
	 * Rewriting the file map / done set on every 4s poll would hammer the
	 * options table (the map alone can be hundreds of KB on large sites), so
	 * the rewrite is gated by a short-lived marker transient.
	 */
	private const TOUCH_INTERVAL = 1800;

	/**
	 * {@inheritdoc}
	 */
	public function save_file_map( string $job_id, array $payload ): void {
		set_transient( self::PREFIX . 'job_' . $job_id, $payload, self::TTL );
	}

	/**
	 * {@inheritdoc}
	 */
	public function load_file_map( string $job_id ): array {
		$cached = get_transient( self::PREFIX . 'job_' . $job_id );
		return is_array( $cached ) ? $cached : array();
	}

	/**
	 * {@inheritdoc}
	 */
	public function save_done( string $job_id, array $done ): void {
		set_transient( self::PREFIX . 'done_' . $job_id, $done, self::TTL );
	}

	/**
	 * {@inheritdoc}
	 */
	public function load_done( string $job_id ): array {
		$cached = get_transient( self::PREFIX . 'done_' . $job_id );
		return is_array( $cached ) ? $cached : array();
	}

	/**
	 * {@inheritdoc}
	 */
	public function save_progress( string $job_id, array $progress ): void {
		set_transient( self::PREFIX . 'progress_' . $job_id, $progress, self::TTL );
	}

	/**
	 * {@inheritdoc}
	 */
	public function load_progress( string $job_id ): array {
		$cached = get_transient( self::PREFIX . 'progress_' . $job_id );
		return is_array( $cached ) ? $cached : array();
	}

	/**
	 * {@inheritdoc}
	 */
	public function save_failures( string $job_id, int $count ): void {
		set_transient( self::PREFIX . 'fail_' . $job_id, $count, self::TTL );
	}

	/**
	 * {@inheritdoc}
	 */
	public function load_failures( string $job_id ): int {
		return (int) get_transient( self::PREFIX . 'fail_' . $job_id );
	}

	/**
	 * {@inheritdoc}
	 */
	public function delete_failures( string $job_id ): void {
		delete_transient( self::PREFIX . 'fail_' . $job_id );
	}

	/**
	 * {@inheritdoc}
	 */
	public function refresh_ttl( string $job_id ): void {
		$touch_key = self::PREFIX . 'touch_' . $job_id;
		if ( false !== get_transient( $touch_key ) ) {
			return; // Refreshed recently.
		}
		set_transient( $touch_key, 1, self::TOUCH_INTERVAL );

		$map = $this->load_file_map( $job_id );
		if ( array() !== $map ) {
			set_transient( self::PREFIX . 'job_' . $job_id, $map, self::TTL );
		}

		$done = $this->load_done( $job_id );
		if ( array() !== $done ) {
			set_transient( self::PREFIX . 'done_' . $job_id, $done, self::TTL );
		}

		$progress = $this->load_progress( $job_id );
		if ( array() !== $progress ) {
			set_transient( self::PREFIX . 'progress_' . $job_id, $progress, self::TTL );
		}

		// The consecutive-failure counter drives the MAX_STATUS_FAILURES
		// escalation; losing it mid-scan would restart the count.
		$failures = $this->load_failures( $job_id );
		if ( $failures > 0 ) {
			set_transient( self::PREFIX . 'fail_' . $job_id, $failures, self::TTL );
		}
	}
}
