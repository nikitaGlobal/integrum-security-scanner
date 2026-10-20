<?php
/**
 * Imunify Connect scanner client.
 *
 * Implements the real Imunify Connect job protocol:
 *   1. POST /scan/start with a file manifest (path, size, modified_at) -> job_id.
 *   2. GET  /jobs/{id}/results (polled): reports per-file actions and verdicts.
 *   3. For action=needs_sha256 -> POST /jobs/{id}/hashes with [{file_id, sha256}].
 *   4. For action=needs_upload  -> POST /jobs/{id}/upload (multipart) per file.
 *   5. When is_complete -> verdicts are read from the same /results payload.
 *
 * @package Integrum\SecurityScanner\Models
 */

declare( strict_types = 1 );

namespace Integrum\SecurityScanner\Models;

use Integrum\SecurityScanner\Contracts\CredentialStorageInterface;
use Integrum\SecurityScanner\Contracts\FileCollectorInterface;
use Integrum\SecurityScanner\Contracts\HttpClientInterface;
use Integrum\SecurityScanner\Contracts\HttpException;
use Integrum\SecurityScanner\Contracts\JobStoreInterface;
use Integrum\SecurityScanner\Contracts\LoggerInterface;
use Integrum\SecurityScanner\Contracts\ScanException;

/**
 * Talks directly to Imunify Connect using a job model: start -> poll -> results.
 */
final class ImunifyScanner implements \Integrum\SecurityScanner\Contracts\ScannerInterface {

	/**
	 * Files larger than this are skipped to keep uploads bounded.
	 */
	private const MAX_FILE_BYTES = 2 * 1024 * 1024;

	/**
	 * Consecutive status poll failures after which the job is surfaced as failed.
	 */
	private const MAX_STATUS_FAILURES = 5;

	/**
	 * Maximum SHA-256 computations submitted per status poll.
	 *
	 * Hashing is fast (a few ms per file), but computing thousands in a single
	 * AJAX request blocks the PHP process and times out. This keeps each poll
	 * bounded so get_status() returns promptly and the poller can advance.
	 */
	private const MAX_HASHES_PER_POLL = 100;

	/**
	 * Maximum file uploads per status poll.
	 *
	 * Each upload is a synchronous multipart HTTP round-trip (~1-2s). Uploading
	 * hundreds in one poll would block for minutes; three was too slow for
	 * jobs with thousands of unknown files (hours to finish). 10 keeps each
	 * poll under the AJAX timeout while still making real progress.
	 */
	private const MAX_UPLOADS_PER_POLL = 10;

	/**
	 * Maps an Imunify verdict to the plugin's status vocabulary.
	 *
	 * @var array<string, string>
	 */
	private const VERDICT_STATUS = array(
		'malicious'  => 'infected',
		'suspicious' => 'suspicious',
		'clean'      => 'clean',
	);

	/**
	 * Maps an Imunify verdict to a UI severity bucket.
	 *
	 * @var array<string, string>
	 */
	private const VERDICT_SEVERITY = array(
		'malicious'  => 'critical',
		'suspicious' => 'medium',
		'clean'      => 'info',
	);

	/**
	 * Job statuses that map to a terminal "completed" state.
	 *
	 * @var string[]
	 */
	private const STATUSES_COMPLETED = array( 'completed', 'done' );

	/**
	 * Job statuses that map to a terminal "failed" state.
	 *
	 * @var string[]
	 */
	private const STATUSES_FAILED = array( 'failed', 'error' );

	/**
	 * Pseudo-progress shown once work has started but the backend has not
	 * reported totals yet — signals "alive" without inventing a percentage.
	 */
	private const PROGRESS_ALIVE_PCT = 5;

	/**
	 * Scanner API base URL.
	 *
	 * @var string
	 */
	private string $base;

	/**
	 * Constructor dependencies.
	 *
	 * @param HttpClientInterface        $http           HTTP client.
	 * @param LoggerInterface            $logger         Logger.
	 * @param CredentialStorageInterface $storage        Credential storage.
	 * @param JobStoreInterface          $store          Per-job state persistence.
	 * @param FileCollectorInterface     $file_collector Candidate file list builder.
	 * @param string                     $domain         Site domain.
	 * @param string|null                $base           Override base URL (tests).
	 */
	public function __construct(
		private HttpClientInterface $http,
		private LoggerInterface $logger,
		private CredentialStorageInterface $storage,
		private JobStoreInterface $store,
		private FileCollectorInterface $file_collector,
		private string $domain,
		?string $base = null
	) {
		$this->base = $base ?? ( defined( 'INTEGRUM_SECURITY_SCANNER_SCANNER_API_BASE' ) ? INTEGRUM_SECURITY_SCANNER_SCANNER_API_BASE : 'https://connect.imunify.com' );
	}

	/**
	 * {@inheritdoc}
	 *
	 * @throws ScanException On failure.
	 */
	public function start_scan( array $directories, array $include_masks, array $exclude_masks ): string {
		$key  = $this->require_key();
		$root = $this->resolve_root( $directories );
		$rels = $this->file_collector->collect( $directories, $include_masks, $exclude_masks, $root );

		$manifest    = array();
		$index       = 0;
		$map         = array();
		$sizes       = array();
		$total_bytes = 0;
		foreach ( $rels as $rel ) {
			$size = $this->file_size( $root, $rel );
			if ( null === $size ) {
				continue;
			}

			$manifest[]      = array(
				'path'        => $rel,
				'file_index'  => $index,
				'size'        => $size,
				'modified_at' => $this->file_mtime( $root, $rel ),
			);
			$map[ $index ]   = $rel;
			$sizes[ $index ] = $size;
			$total_bytes    += $size;
			++$index;
		}

		$resp = $this->call( 'POST', '/scan/start', $key, array( 'files' => $manifest ) );

		if ( empty( $resp['body']['job_id'] ) ) {
			throw new ScanException( __( 'No job_id returned by scanner.', 'integrum-security-scanner' ) );
		}

		$job_id = (string) $resp['body']['job_id'];
		$this->store_file_map( $job_id, $root, $map, $sizes, $total_bytes );

		return $job_id;
	}

	/**
	 * {@inheritdoc}
	 *
	 * @throws ScanException On transport / auth failure.
	 */
	public function get_status( string $scan_job_id ): array {
		$key = $this->require_key();

		try {
			$results = $this->fetch_results( $scan_job_id, $key );
			$body    = $results['body'];
			$map     = $this->store->load_file_map( $scan_job_id );

			// The per-job state (file map, done set, progress) lives in
			// transients with a 1-hour TTL. When it expires while the job is
			// still processing, the client can no longer satisfy any pending
			// needs_sha256 / needs_upload action and would silently spin in
			// "processing" forever (observed in production as a scan stuck
			// for hours). Fail fast and journal it instead.
			if ( $this->job_state_expired( $map, $body ) ) {
				$this->logger->error(
					'scan job state expired',
					array(
						'job_id' => $scan_job_id,
						'hint'   => 'job transients expired while the scan is still processing; failing the job instead of looping forever',
					)
				);

				return array(
					'status'       => 'failed',
					'progress_pct' => 0,
				);
			}

			// A needs_* action referencing a file_index that is not in the
			// manifest map can never be satisfied either — same eternal
			// "processing" loop, different trigger. Fail fast and journal.
			$paths      = is_array( $map['paths'] ?? null ) ? $map['paths'] : array();
			$unresolved = $this->count_unresolvable_actions( $body, $paths );
			if ( $unresolved > 0 ) {
				$this->logger->error(
					'pending scan action could not be resolved to a file path',
					array(
						'job_id'     => $scan_job_id,
						'unresolved' => $unresolved,
					)
				);

				return array(
					'status'       => 'failed',
					'progress_pct' => 0,
				);
			}

			$this->process_actions( $scan_job_id, $key, $body );
		} catch ( ScanException $e ) {
			if ( 401 === $e->getCode() ) {
				throw $e;
			}

			// Non-fatal at first: surface "processing" so the poller keeps trying.
			// Escalate to "failed" once the same job has failed too many times in
			// a row, otherwise the UI would show "scanning" forever.
			$failures = $this->increment_failures( $scan_job_id );
			$this->logger->error(
				'status poll failed',
				array(
					'message'  => $e->getMessage(),
					'failures' => $failures,
				)
			);

			if ( $failures >= self::MAX_STATUS_FAILURES ) {
				$this->store->delete_failures( $scan_job_id );
				return array(
					'status'       => 'failed',
					'progress_pct' => 0,
				);
			}

			return array(
				'status'       => 'processing',
				'progress_pct' => 0,
			);
		}

		$this->store->delete_failures( $scan_job_id );

		$status = $this->normalise_status( (string) ( $body['status'] ?? 'processing' ) );

		// Keep the per-job state alive while the poller keeps polling: extend
		// the transients' TTL so long scans do not lose their file map.
		if ( 'processing' === $status ) {
			$this->store->refresh_ttl( $scan_job_id );
		}

		// Surface the first file that is still pending an action. The real API
		// exposes only file_index (not a path), so we resolve the human-readable
		// path from the manifest map stored at scan start ($map loaded above).
		$current_file = '';
		foreach ( (array) ( $body['files'] ?? array() ) as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			if ( isset( $row['action'] ) && 'has_verdict' !== $row['action'] ) {
				$rel = (string) ( $row['path'] ?? '' );
				if ( '' === $rel ) {
					$rel = (string) ( $paths[ (int) ( $row['file_index'] ?? -1 ) ] ?? '' );
				}
				$current_file = '/' . ltrim( $rel, '/' );
				break;
			}
		}

		$completed   = (int) ( $body['completed_files'] ?? 0 );
		$total_files = (int) ( $body['total_files'] ?? 0 );
		$total_bytes = (int) ( $map['total_bytes'] ?? 0 );

		// scanned_bytes reflects client work (files hashed/uploaded), but the
		// scanner also resolves files server-side — those never appear in the
		// pending action list, so their size is never charged by process_actions.
		// Floor the byte counter at the proportional share of completed files so
		// the byte readout stays consistent with the percentage and server-resolved
		// (e.g. hash-cached) files are accounted for. The exact per-file tracking
		// still wins when the client leads (early polling, before verdicts mature).
		$tracked       = (int) ( $this->store->load_progress( $scan_job_id )['scanned_bytes'] ?? 0 );
		$expected      = $total_files > 0 && $total_bytes > 0
			? (int) round( $total_bytes * $completed / $total_files )
			: 0;
		$scanned_bytes = max( $tracked, $expected );

		return array(
			'status'        => $status,
			'progress_pct'  => $this->progress( $body ),
			'current_file'  => $current_file,
			'completed'     => $completed,
			'total'         => $total_files,
			'total_bytes'   => $total_bytes,
			'scanned_bytes' => $scanned_bytes,
			'started_at'    => (int) ( $map['started_at'] ?? 0 ),
		);
	}

	/**
	 * {@inheritdoc}
	 *
	 * @throws ScanException On transport / auth failure.
	 */
	public function get_results( string $scan_job_id ): array {
		$key     = $this->require_key();
		$results = $this->fetch_results( $scan_job_id, $key );
		$body    = $results['body'];

		$map   = $this->store->load_file_map( $scan_job_id );
		$paths = is_array( $map['paths'] ?? null ) ? $map['paths'] : array();

		$out = array();
		foreach ( (array) ( $body['files'] ?? array() ) as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			if ( 'has_verdict' !== (string) ( $row['action'] ?? '' ) ) {
				continue;
			}
			$out[] = $this->to_result( $row, $paths );
		}

		return $out;
	}

	/**
	 * Resolves the root path used to compute relative file paths.
	 *
	 * Prefers get_home_path() (the supported API for the WordPress install
	 * root, same source as AdminController::site_root()). When it is
	 * unavailable (e.g. in unit tests), falls back to the first selected
	 * directory so the collector's relative paths line up with the manifest
	 * paths the scanner expects.
	 *
	 * @param string[] $directories Absolute paths.
	 */
	private function resolve_root( array $directories ): string {
		if ( function_exists( 'get_home_path' ) ) {
			return rtrim( (string) get_home_path(), '/\\' );
		}

		$first = array() === $directories ? '' : (string) reset( $directories );
		return '' === $first ? '.' : rtrim( $first, '/\\' );
	}

	/**
	 * Fetches the combined status + per-file payload from /results.
	 *
	 * @param string $job_id Job id.
	 * @param string $key    Site key.
	 * @return array{code: int, body: array<string, mixed>}
	 *
	 * @throws ScanException On unrecoverable failure.
	 */
	private function fetch_results( string $job_id, string $key ): array {
		return $this->call( 'GET', '/jobs/' . rawurlencode( $job_id ) . '/results', $key );
	}

	/**
	 * True when the per-job state has expired while the job still needs it.
	 *
	 * The file map / done set / progress transients expire after an hour. A
	 * job that is still processing AND still reports pending client actions
	 * (needs_sha256 / needs_upload) can never finish without that state, so
	 * it must be surfaced as failed instead of spinning in "processing".
	 *
	 * @param array<string, mixed> $map  Stored file map (empty when expired).
	 * @param array<string, mixed> $body Last /results body.
	 */
	private function job_state_expired( array $map, array $body ): bool {
		if ( array() !== $map ) {
			return false; // State is alive.
		}

		if ( ! empty( $body['is_complete'] ) ) {
			return false; // Job finished; nothing left to drive.
		}

		if ( 'processing' !== $this->normalise_status( (string) ( $body['status'] ?? 'processing' ) ) ) {
			return false; // Job already terminal server-side.
		}

		foreach ( (array) ( $body['files'] ?? array() ) as $row ) {
			if ( is_array( $row ) && 'has_verdict' !== (string) ( $row['action'] ?? '' ) ) {
				return true; // Pending client work, but the state to do it is gone.
			}
		}

		return false;
	}

	/**
	 * Counts pending needs_* actions whose file_index is not in the map.
	 *
	 * Such actions can never be satisfied (the index did not come from our
	 * manifest), so the job would loop forever. A count > 0 means the job
	 * should fail fast.
	 *
	 * @param array<string, mixed> $body  Last /results body.
	 * @param array<int, string>   $paths file_index => relative path.
	 */
	private function count_unresolvable_actions( array $body, array $paths ): int {
		$count = 0;

		foreach ( (array) ( $body['files'] ?? array() ) as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}

			$action = (string) ( $row['action'] ?? '' );
			if ( ! in_array( $action, array( 'needs_sha256', 'needs_upload' ), true ) ) {
				continue;
			}

			$file_index = (int) ( $row['file_index'] ?? -1 );
			$rel        = (string) ( $paths[ $file_index ] ?? '' );
			if ( '' === $rel ) {
				++$count;
			}
		}

		return $count;
	}

	/**
	 * Satisfies needs_sha256 / needs_upload actions reported by the scanner.
	 *
	 * The real /results payload can list thousands of files at once. Processing
	 * them all in a single synchronous call would block the AJAX request for
	 * many minutes (hashing 18k files + uploading hundreds). Instead, each poll
	 * processes only a bounded batch and records what it has already handled
	 * in a per-job "done" set, so the next poll resumes from where it left off
	 * instead of re-doing the same files.
	 *
	 * @param string               $job_id Job id.
	 * @param string               $key    Site key.
	 * @param array<string, mixed> $body   Last /results body.
	 *
	 * @throws ScanException On unrecoverable failure (auth, repeated 5xx).
	 */
	private function process_actions( string $job_id, string $key, array $body ): void {
		$files = is_array( $body['files'] ?? null ) ? $body['files'] : array();
		$map   = $this->store->load_file_map( $job_id );
		$root  = $map['root'] ?? '';
		$paths = is_array( $map['paths'] ?? null ) ? $map['paths'] : array();
		$sizes = is_array( $map['sizes'] ?? null ) ? $map['sizes'] : array();

		$done          = $this->store->load_done( $job_id );
		$progress      = $this->store->load_progress( $job_id );
		$scanned_bytes = (int) ( $progress['scanned_bytes'] ?? 0 );
		// Track which file_index values have already been charged so the same
		// file flowing through needs_sha256 → needs_upload is counted only once.
		// Keyed by file_index (stable, client-assigned), not file_id.
		$charged        = is_array( $progress['charged'] ?? null ) ? $progress['charged'] : array();
		$hash_batch     = array();
		$uploads        = 0;
		$hash_limit     = self::MAX_HASHES_PER_POLL;
		$upload_cap     = self::MAX_UPLOADS_PER_POLL;
		$mutated        = false;
		$progress_dirty = false;

		foreach ( $files as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}

			$action     = (string) ( $row['action'] ?? '' );
			$file_id    = (string) ( $row['file_id'] ?? '' );
			$file_index = (int) ( $row['file_index'] ?? -1 );

			// The done key is namespaced per-action, not per-file: a file flows
			// through needs_sha256 -> needs_upload -> has_verdict, and satisfying
			// one stage must not mark it done for the next stage. Otherwise the
			// server flips a hashed-but-unknown file to needs_upload and we would
			// skip it forever.
			$done_key = $action . ':' . $file_id;
			if ( '' !== $file_id && isset( $done[ $done_key ] ) ) {
				continue;
			}

			$rel = $paths[ $file_index ] ?? '';
			$abs = '' !== $rel ? $this->join( $root, $rel ) : '';

			// Size of this file. Charged against scanned_bytes ONLY when we actually
			// do work on it this poll (submit a hash or upload it). Charging every
			// row upfront would be wrong: the real /results body lists every pending
			// file at once, while we only process a bounded batch per poll — charging
			// them all instantly would max out the byte readout at 0% progress
			// (e.g. "134 MB / 134 MB").
			$file_size = (int) ( $sizes[ $file_index ] ?? 0 );

			if ( 'needs_sha256' === $action && '' !== $abs ) {
				if ( count( $hash_batch ) >= $hash_limit ) {
					continue; // Bounded: leave the rest for the next poll.
				}
				$sha = $this->sha256( $abs );
				if ( null !== $sha && '' !== $file_id ) {
					$hash_batch[]      = array(
						'file_id' => $file_id,
						'sha256'  => $sha,
					);
					$done[ $done_key ] = true;
					$mutated           = true;
					// Charge once per physical file (file_index), on the first stage we
					// actually satisfy — see charge_file() for the dedup rationale.
					if ( $this->charge_file( $file_index, $file_size, $charged, $scanned_bytes ) ) {
						$progress_dirty = true;
					}
				}
				continue;
			}

			if ( 'needs_upload' === $action && '' !== $abs && '' !== $file_id ) {
				if ( $uploads >= $upload_cap ) {
					continue; // Bounded: leave the rest for the next poll.
				}
				$this->upload_one( $job_id, $key, $abs, $file_id );
				$done[ $done_key ] = true;
				$mutated           = true;
				++$uploads;
				if ( $this->charge_file( $file_index, $file_size, $charged, $scanned_bytes ) ) {
					$progress_dirty = true;
				}
			}
		}

		if ( array() !== $hash_batch ) {
			$this->call( 'POST', '/jobs/' . rawurlencode( $job_id ) . '/hashes', $key, array( 'hashes' => $hash_batch ) );
			$this->logger->debug( 'submitted hashes', array( 'count' => count( $hash_batch ) ) );
		}

		if ( $mutated ) {
			$this->store->save_done( $job_id, $done );
		}

		if ( $progress_dirty ) {
			$this->store->save_progress(
				$job_id,
				array(
					'scanned_bytes' => $scanned_bytes,
					'charged'       => $charged,
				)
			);
		}
	}

	/**
	 * Charges a file's size against the running scanned_bytes total once.
	 *
	 * Dedup is keyed on file_index (the stable, client-assigned manifest
	 * identifier), NOT on file_id: the server reassigns file_id when a file
	 * advances from needs_sha256 to needs_upload, so keying on file_id would
	 * double-charge the same physical file and push scanned_bytes past
	 * total_bytes (e.g. 978 KB / 808 KB). Returns false (no charge) when the
	 * file was already charged or its index is unknown.
	 *
	 * @param int              $file_index    Manifest index of the file, or -1.
	 * @param int              $file_size     Bytes to charge.
	 * @param array<int, true> $charged       Already-charged indexes (modified).
	 * @param int              $scanned_bytes Running byte total (modified).
	 * @return bool True if this call charged the file; false if already charged.
	 */
	private function charge_file( int $file_index, int $file_size, array &$charged, int &$scanned_bytes ): bool {
		if ( $file_index < 0 || isset( $charged[ $file_index ] ) ) {
			return false;
		}

		$charged[ $file_index ] = true;
		$scanned_bytes         += $file_size;
		return true;
	}

	/**
	 * Uploads a single file for content scanning.
	 *
	 * @param string $job_id  Job id.
	 * @param string $key     Site key.
	 * @param string $abs     Absolute path.
	 * @param string $file_id Imunify file_id.
	 *
	 * @throws ScanException On unrecoverable failure.
	 */
	private function upload_one( string $job_id, string $key, string $abs, string $file_id ): void {
		if ( ! is_file( $abs ) || ! is_readable( $abs ) ) {
			$this->logger->debug( 'upload skipped, unreadable', array( 'path' => basename( $abs ) ) );
			return;
		}
		if ( filesize( $abs ) > self::MAX_FILE_BYTES ) {
			$this->logger->debug( 'upload skipped, oversized', array( 'path' => basename( $abs ) ) );
			return;
		}

		$url = $this->base . '/api/v1/jobs/' . rawurlencode( $job_id ) . '/upload';
		try {
			$resp = $this->http->upload( $url, $abs, $file_id, $key );
		} catch ( HttpException $e ) {
			throw new ScanException( __( 'Upload failed.', 'integrum-security-scanner' ), 0, $e );
		}

		if ( $resp['code'] < 200 || $resp['code'] >= 300 ) {
			throw new ScanException(
				sprintf(
					/* translators: %d: HTTP status code returned by the scanner API. */
					__( 'Upload rejected: HTTP %d.', 'integrum-security-scanner' ),
					(int) $resp['code']
				)
			);
		}
	}

	/**
	 * Performs a JSON call with one automatic retry on 5xx/transport errors.
	 *
	 * @param string               $method HTTP method.
	 * @param string               $path   Path under /api/v1.
	 * @param string               $key    Site key.
	 * @param array<string, mixed> $body   Body.
	 * @return array{code: int, body: array<string, mixed>}
	 *
	 * @throws ScanException On unrecoverable failure.
	 */
	private function call( string $method, string $path, string $key, array $body = array() ): array {
		$url = $this->base . '/api/v1' . $path;

		try {
			$resp = $this->http->request( $method, $url, $body, $key );
		} catch ( HttpException $e ) {
			$this->logger->error( 'scanner transport error, retrying once', array( 'path' => $path ) );

			try {
				$resp = $this->http->request( $method, $url, $body, $key );
			} catch ( HttpException $e2 ) {
				throw new ScanException( __( 'Scanner is temporarily unavailable.', 'integrum-security-scanner' ), 0, $e2 );
			}
		}

		if ( $resp['code'] >= 500 ) {
			$this->logger->error(
				'scanner 5xx, retrying once',
				array(
					'path' => $path,
					'code' => $resp['code'],
				)
			);
			try {
				$resp = $this->http->request( $method, $url, $body, $key );
			} catch ( HttpException $e ) {
				throw new ScanException( __( 'Scanner returned server error.', 'integrum-security-scanner' ), 0, $e );
			}
		}

		if ( 401 === $resp['code'] || 403 === $resp['code'] ) {
			throw $this->auth_error( $resp );
		}

		if ( $resp['code'] < 200 || $resp['code'] >= 300 ) {
			throw new ScanException(
				sprintf(
					/* translators: %d: HTTP status code returned by the scanner API. */
					__( 'Scanner error: HTTP %d.', 'integrum-security-scanner' ),
					(int) $resp['code']
				)
			);
		}

		return $resp;
	}

	/**
	 * Builds a ScanException for a 401/403 response.
	 *
	 * A 403 "quota_exceeded" is NOT an auth error: the key is valid, the plan
	 * limit was reached. Surfacing it with code 401 would make the UI tell the
	 * user to fetch a new key, which is wrong. We preserve the real API message
	 * and use code 403 so the caller can distinguish the two cases.
	 *
	 * @param array{code: int, body: array<string, mixed>} $resp Decoded response.
	 *
	 * @return ScanException Ready to throw.
	 */
	private function auth_error( array $resp ): ScanException {
		$http_code = (int) $resp['code'];
		$body      = is_array( $resp['body'] ?? null ) ? $resp['body'] : array();
		$api_code  = (string) ( $body['code'] ?? '' );
		$message   = (string) ( $body['error'] ?? '' );

		// Quota / rate-limit: the key is valid, the limit was hit.
		if ( 403 === $http_code && 'quota_exceeded' === $api_code ) {
			$msg    = '' !== $message ? $message : __( 'Scan quota exceeded.', 'integrum-security-scanner' );
			$quota  = is_array( $body['quota'] ?? null ) ? $body['quota'] : array();
			$resets = (int) ( $quota['resets_in'] ?? 0 );
			if ( $resets > 0 ) {
				$days = max( 1, (int) round( $resets / 86400 ) );
				$msg .= ' ' . sprintf(
					/* translators: %d: number of days until the scan quota resets. */
					_n( 'Resets in %d day.', 'Resets in %d days.', $days, 'integrum-security-scanner' ),
					$days
				);
			}
			return new ScanException( $msg, 403 );
		}

		if ( '' === $message ) {
			$message = 401 === $http_code
				? __( 'Invalid site key.', 'integrum-security-scanner' )
				: __( 'Scanner rejected the request.', 'integrum-security-scanner' );
		}

		return new ScanException( $message, 401 === $http_code ? 401 : 403 );
	}

	/**
	 * Maps a raw file row to a ScanResult DTO.
	 *
	 * @param array<string, mixed> $row /results.files[*] entry.
	 */
	private function to_result( array $row, array $paths = array() ): ScanResult {
		$verdict = (string) ( $row['verdict'] ?? 'pending' );

		$path = (string) ( $row['path'] ?? '' );
		if ( '' === $path ) {
			$path = (string) ( $paths[ (int) ( $row['file_index'] ?? -1 ) ] ?? '' );
		}

		return new ScanResult(
			$path,
			$this->verdict_to_status( $verdict ),
			(string) ( $row['signature_name'] ?? ( $row['threat_type'] ?? '' ) ),
			$this->verdict_to_severity( $verdict ),
			isset( $row['scanned_at'] ) ? (string) $row['scanned_at'] : null,
			$this->result_detail( $row, $verdict )
		);
	}

	/**
	 * Extracts the raw Imunify response fields surfaced in the results detail
	 * view. Only known scalar fields with a non-empty value are kept, so the UI
	 * never renders unexpected payload noise.
	 *
	 * @param array<string, mixed> $row     /results.files[*] entry.
	 * @param string               $verdict Raw verdict.
	 * @return array<string, string>
	 */
	private function result_detail( array $row, string $verdict ): array {
		$fields = array(
			'verdict'        => $verdict,
			'signature_name' => (string) ( $row['signature_name'] ?? '' ),
			'file_id'        => (string) ( $row['file_id'] ?? '' ),
			'sha256'         => (string) ( $row['sha256'] ?? '' ),
			'scanned_at'     => isset( $row['scanned_at'] ) ? (string) $row['scanned_at'] : '',
		);

		return array_filter( $fields, 'strlen' );
	}

	/**
	 * Maps an Imunify verdict to the plugin's status vocabulary.
	 *
	 * @param string $verdict clean|malicious|suspicious|pending.
	 */
	private function verdict_to_status( string $verdict ): string {
		return self::VERDICT_STATUS[ $verdict ] ?? 'unknown';
	}

	/**
	 * Maps an Imunify verdict to a severity bucket for the UI badge.
	 *
	 * @param string $verdict Verdict.
	 */
	private function verdict_to_severity( string $verdict ): string {
		return self::VERDICT_SEVERITY[ $verdict ] ?? 'low';
	}

	/**
	 * Normalises the scanner job status into the plugin vocabulary.
	 *
	 * @param string $status Raw status.
	 */
	private function normalise_status( string $status ): string {
		$status = strtolower( $status );
		if ( in_array( $status, self::STATUSES_FAILED, true ) ) {
			return 'failed';
		}
		if ( in_array( $status, self::STATUSES_COMPLETED, true ) ) {
			return 'completed';
		}
		return 'processing';
	}

	/**
	 * Computes a 0-100 progress percentage from the results body.
	 *
	 * @param array<string, mixed> $body Results body.
	 */
	private function progress( array $body ): int {
		if ( ! empty( $body['is_complete'] ) ) {
			return 100;
		}

		$total = (int) ( $body['total_files'] ?? 0 );
		$done  = (int) ( $body['completed_files'] ?? 0 );
		if ( $total <= 0 ) {
			// Backend has not reported totals yet; signal "alive" without
			// inventing a fake half-done percentage.
			return 0 === $done ? 0 : self::PROGRESS_ALIVE_PCT;
		}
		if ( $done >= $total ) {
			return 100;
		}
		return (int) round( $done / $total * 100 );
	}

	/**
	 * Resolves the current site_key or throws.
	 *
	 * @throws ScanException When no key is configured.
	 */
	private function require_key(): string {
		$key = $this->storage->get_site_key();
		if ( null === $key || '' === $key ) {
			throw new ScanException( 'No site key configured.', 401 );
		}

		return $key;
	}

	/**
	 * Returns the size of a file or null when unreadable/oversized.
	 *
	 * @param string $root Root path.
	 * @param string $rel  Relative path.
	 */
	private function file_size( string $root, string $rel ): ?int {
		$abs = $this->resolve_safe( $root, $rel );
		if ( null === $abs ) {
			return null;
		}
		$size = filesize( $abs );
		if ( false === $size || $size > self::MAX_FILE_BYTES ) {
			return null;
		}
		return (int) $size;
	}

	/**
	 * Returns a file mtime or zero.
	 *
	 * @param string $root Root path.
	 * @param string $rel  Relative path.
	 */
	private function file_mtime( string $root, string $rel ): int {
		$abs = $this->resolve_safe( $root, $rel );
		if ( null === $abs ) {
			return 0;
		}
		$mtime = filemtime( $abs );
		return false === $mtime ? 0 : (int) $mtime;
	}

	/**
	 * Computes the SHA-256 of a file or null on failure.
	 *
	 * @param string $abs Absolute path (already validated).
	 */
	private function sha256( string $abs ): ?string {
		if ( ! is_file( $abs ) || ! is_readable( $abs ) ) {
			return null;
		}
		$hash = hash_file( 'sha256', $abs );
		return false === $hash ? null : $hash;
	}

	/**
	 * Joins a root and a relative path and rejects traversal / symlink escape.
	 *
	 * @param string $root Root.
	 * @param string $rel  Relative path (forward slashes).
	 * @return string|null Absolute real path inside $root, or null when unsafe.
	 */
	private function resolve_safe( string $root, string $rel ): ?string {
		$rel   = str_replace( '\\', '/', $rel );
		$parts = array_filter( explode( '/', $rel ), 'strlen' );
		foreach ( $parts as $part ) {
			if ( '.' === $part || '..' === $part ) {
				return null;
			}
		}

		$root_real = realpath( $root );
		if ( false === $root_real ) {
			return null;
		}

		$candidate = $root_real . DIRECTORY_SEPARATOR . implode( DIRECTORY_SEPARATOR, $parts );
		$resolved  = realpath( $candidate );
		if ( false === $resolved || ! is_file( $resolved ) || ! is_readable( $resolved ) ) {
			return null;
		}

		if ( $resolved !== $root_real && 0 !== strpos( $resolved, $root_real . DIRECTORY_SEPARATOR ) ) {
			return null;
		}

		return $resolved;
	}

	/**
	 * Joins a root and a relative path using the OS separator (unsafe; prefer resolve_safe).
	 *
	 * @param string $root Root.
	 * @param string $rel  Relative path (forward slashes).
	 */
	private function join( string $root, string $rel ): string {
		$safe = $this->resolve_safe( $root, $rel );
		return null !== $safe ? $safe : '';
	}

	/**
	 * Persists the file_index -> relative path map for later polling.
	 *
	 * Also stores the per-file sizes and aggregate totals so the status poller
	 * can surface scanned/total bytes and compute an ETA without re-statting.
	 *
	 * @param string            $job_id      Job id.
	 * @param string            $root        Root path.
	 * @param array<int,string> $paths       file_index => relative path.
	 * @param array<int,int>    $sizes       file_index => size in bytes.
	 * @param int               $total_bytes Sum of all file sizes.
	 */
	private function store_file_map( string $job_id, string $root, array $paths, array $sizes = array(), int $total_bytes = 0 ): void {
		$this->store->save_file_map(
			$job_id,
			array(
				'root'        => $root,
				'paths'       => $paths,
				'sizes'       => $sizes,
				'total_bytes' => $total_bytes,
				'started_at'  => time(),
			)
		);
	}

	/**
	 * Increments the consecutive failure counter for a job.
	 *
	 * @param string $job_id Job id.
	 * @return int New failure count.
	 */
	private function increment_failures( string $job_id ): int {
		$count = $this->store->load_failures( $job_id ) + 1;
		$this->store->save_failures( $job_id, $count );
		return $count;
	}
}
