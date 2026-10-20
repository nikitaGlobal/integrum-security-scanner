<?php
/**
 * Per-job scan session persistence contract.
 *
 * Decouples ImunifyScanner from the storage mechanism (WP Transients API in
 * production, an in-memory map in tests). Every method is keyed by job id.
 *
 * @package Integrum\SecurityScanner\Contracts
 */

declare( strict_types = 1 );

namespace Integrum\SecurityScanner\Contracts;

/**
 * Persists the mutable per-job state needed across status polls.
 */
interface JobStoreInterface {

	/**
	 * Stores the file_index -> path map and aggregate totals for a job.
	 *
	 * @param string               $job_id  Job id.
	 * @param array<string, mixed> $payload {root, paths, sizes, total_bytes, started_at}.
	 */
	public function save_file_map( string $job_id, array $payload ): void;

	/**
	 * Loads the file map payload, or an empty array when absent.
	 *
	 * @param string $job_id Job id.
	 * @return array<string, mixed>
	 */
	public function load_file_map( string $job_id ): array;

	/**
	 * Stores the per-job satisfied-action set.
	 *
	 * @param string              $job_id Job id.
	 * @param array<string, bool> $done   done-key => true.
	 */
	public function save_done( string $job_id, array $done ): void;

	/**
	 * Loads the satisfied-action set, or an empty array when absent.
	 *
	 * @param string $job_id Job id.
	 * @return array<string, bool>
	 */
	public function load_done( string $job_id ): array;

	/**
	 * Stores the cumulative progress counters for a job.
	 *
	 * @param string               $job_id   Job id.
	 * @param array<string, mixed> $progress {scanned_bytes, charged}.
	 */
	public function save_progress( string $job_id, array $progress ): void;

	/**
	 * Loads the progress counters, or an empty array when absent.
	 *
	 * @param string $job_id Job id.
	 * @return array<string, mixed>
	 */
	public function load_progress( string $job_id ): array;

	/**
	 * Stores the consecutive failure counter for a job.
	 *
	 * @param string $job_id Job id.
	 * @param int    $count  Failure count.
	 */
	public function save_failures( string $job_id, int $count ): void;

	/**
	 * Loads the consecutive failure count, defaulting to 0.
	 *
	 * @param string $job_id Job id.
	 */
	public function load_failures( string $job_id ): int;

	/**
	 * Clears the failure counter for a job.
	 *
	 * @param string $job_id Job id.
	 */
	public function delete_failures( string $job_id ): void;

	/**
	 * Extends the lifetime of the stored state for a job.
	 *
	 * The state is kept in transients with a fixed TTL. A long scan outlives
	 * it (uploads are capped per poll, so big sites legitimately run for
	 * hours), so every successful poll refreshes the TTL. Implementations
	 * without a TTL (in-memory stores) may no-op.
	 *
	 * @param string $job_id Job id.
	 */
	public function refresh_ttl( string $job_id ): void;
}
