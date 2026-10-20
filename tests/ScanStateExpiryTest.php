<?php
/**
 * Regression tests for the "scan stuck in processing for hours" incident.
 *
 * Root cause: the per-job state (file map, done set, progress) is stored in
 * transients with a 1-hour TTL. A long scan (uploads are capped per poll, so
 * big sites legitimately run for hours) outlives that TTL: the client can no
 * longer resolve pending needs_sha256/needs_upload actions, the polls keep
 * "succeeding", and the UI stays in processing forever.
 *
 * Expected behaviour:
 *   1. A job whose state expired while still processing must surface as
 *      "failed" AND be journaled via the logger.
 *   2. Successful polls must refresh the state TTL so long scans survive.
 *   3. Pending actions that cannot be resolved to a path must be journaled
 *      and must not leave the job spinning forever.
 *
 * @package Integrum\SecurityScanner\Tests
 */

declare( strict_types = 1 );

namespace Integrum\SecurityScanner\Tests;

use Integrum\SecurityScanner\Models\FileCollector;
use Integrum\SecurityScanner\Models\ImunifyScanner;
use Integrum\SecurityScanner\Models\WpTransientJobStore;
use Integrum\SecurityScanner\Tests\Fixtures\InMemoryCredentialStorage;
use Integrum\SecurityScanner\Tests\Fixtures\MockHttpClient;
use Integrum\SecurityScanner\Tests\Fixtures\SpyLogger;
use PHPUnit\Framework\TestCase;

final class ScanStateExpiryTest extends TestCase {

	/**
	 * Resets the fake transient store and clock before each test.
	 */
	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['__llar_test_transients'] = array();
		$GLOBALS['__llar_test_now']        = time();
	}

	/**
	 * Cleans the fake transient store and clock after each test.
	 */
	protected function tearDown(): void {
		unset( $GLOBALS['__llar_test_transients'], $GLOBALS['__llar_test_now'] );
		parent::tearDown();
	}

	/**
	 * A job whose file map expired while the scanner still reports pending
	 * actions must fail fast (not spin in "processing" forever) and must
	 * leave an error record in the log.
	 */
	public function test_expired_job_state_fails_fast_and_logs(): void {
		$root = $this->mkdir_tree();

		$base = 'https://scanner.test';
		$http = new MockHttpClient();
		$http->add_scenario( 'POST', $base . '/api/v1/scan/start', 200, array( 'job_id' => 'job-exp' ) );
		$http->add_scenario(
			'GET',
			$base . '/api/v1/jobs/job-exp/results',
			200,
			array(
				'status'          => 'processing',
				'is_complete'     => false,
				'total_files'     => 1,
				'completed_files' => 0,
				'files'           => array(
					array(
						'file_id'    => 'fid-a',
						'file_index' => 0,
						'action'     => 'needs_sha256',
					),
				),
			)
		);
		$http->add_scenario( 'POST', $base . '/api/v1/jobs/job-exp/hashes', 200, array( 'processed' => 1 ) );

		$logger = new SpyLogger();
		$s      = $this->make_scanner( $http, $logger, $base );
		$s->start_scan( array( $root ), array( '*.php' ), array() );

		$first = $s->get_status( 'job-exp' );
		$this->assertSame( 'processing', $first['status'], 'fresh job must poll normally before expiry' );

		// One hour passes: the job/done/progress transients expire.
		$GLOBALS['__llar_test_now'] += HOUR_IN_SECONDS + 1;

		$second = $s->get_status( 'job-exp' );

		$this->assertSame( 'failed', $second['status'], 'expired job state must surface as failed, not eternal processing' );
		$this->assertTrue( $logger->has_error_containing( 'expired' ), 'the expiry incident must be journaled' );

		// Fail-fast must happen before any pointless hashing/upload work.
		$urls       = array_map( fn( $r ) => $r['url'], $http->recorded() );
		$hash_posts = array_filter(
			$urls,
			fn( $u ) => false !== strpos( $u, '/hashes' )
		);
		$this->assertCount( 1, $hash_posts, 'no extra hash batch must be submitted after expiry' );

		$this->rm( $root );
	}

	/**
	 * Successful polls must refresh the per-job state TTL: a scan polled at
	 * 35-minute intervals must still have its file map alive at t+70min,
	 * well past the original 1-hour expiry.
	 */
	public function test_successful_polls_refresh_state_ttl(): void {
		$root = $this->mkdir_tree();

		$base = 'https://scanner.test';
		$http = new MockHttpClient();
		$http->add_scenario( 'POST', $base . '/api/v1/scan/start', 200, array( 'job_id' => 'job-ttl' ) );
		$http->add_scenario(
			'GET',
			$base . '/api/v1/jobs/job-ttl/results',
			200,
			array(
				'status'          => 'processing',
				'is_complete'     => false,
				'total_files'     => 1,
				'completed_files' => 0,
				'files'           => array(
					array(
						'file_id'    => 'fid-a',
						'file_index' => 0,
						'action'     => 'needs_sha256',
					),
				),
			)
		);
		$http->add_scenario( 'POST', $base . '/api/v1/jobs/job-ttl/hashes', 200, array( 'processed' => 1 ) );

		$logger = new SpyLogger();
		$s      = $this->make_scanner( $http, $logger, $base );
		$s->start_scan( array( $root ), array( '*.php' ), array() );

		// t0: first poll stores and hashes normally.
		$s->get_status( 'job-ttl' );

		// t0+35min: poll again — must keep the state alive (TTL refreshed).
		$GLOBALS['__llar_test_now'] += 35 * 60;
		$mid                         = $s->get_status( 'job-ttl' );
		$this->assertSame( 'processing', $mid['status'] );

		// t0+70min: past the ORIGINAL 1-hour expiry. Without a TTL refresh
		// the file map would be gone and the job would silently stall.
		$GLOBALS['__llar_test_now'] += 35 * 60;
		$late                        = $s->get_status( 'job-ttl' );

		$this->assertSame( 'processing', $late['status'], 'long-running job must survive past the original TTL when polled' );
		$this->assertGreaterThan( 0, $late['total_bytes'], 'file map must still be alive (total_bytes comes from the map)' );
		$this->assertFalse( $logger->has_error_containing( 'expired' ), 'a live job must not be reported as expired' );

		$this->rm( $root );
	}

	/**
	 * When the file map exists but a needs_sha256/needs_upload action
	 * references a file_index that cannot be resolved to a path, the job can
	 * never progress — it must fail fast and be journaled, not spin forever.
	 */
	public function test_unresolvable_pending_actions_are_logged(): void {
		$root = $this->mkdir_tree();

		$base = 'https://scanner.test';
		$http = new MockHttpClient();
		$http->add_scenario( 'POST', $base . '/api/v1/scan/start', 200, array( 'job_id' => 'job-unres' ) );
		$http->add_scenario(
			'GET',
			$base . '/api/v1/jobs/job-unres/results',
			200,
			array(
				'status'          => 'processing',
				'is_complete'     => false,
				'total_files'     => 1,
				'completed_files' => 0,
				'files'           => array(
					// file_index 42 was never in the manifest.
					array(
						'file_id'    => 'fid-x',
						'file_index' => 42,
						'action'     => 'needs_sha256',
					),
				),
			)
		);

		$logger = new SpyLogger();
		$s      = $this->make_scanner( $http, $logger, $base );
		$s->start_scan( array( $root ), array( '*.php' ), array() );

		$status = $s->get_status( 'job-unres' );

		$this->assertSame( 'failed', $status['status'], 'an unresolvable pending action means the job can never finish' );
		$this->assertTrue(
			$logger->has_error_containing( 'could not be resolved' ),
			'unresolvable pending actions must be journaled'
		);

		$this->rm( $root );
	}

	/**
	 * Builds a scanner wired with the production job store and collector.
	 *
	 * @param MockHttpClient $http   HTTP mock.
	 * @param SpyLogger      $logger Logger.
	 * @param string         $base   API base.
	 */
	private function make_scanner( MockHttpClient $http, SpyLogger $logger, string $base ): ImunifyScanner {
		$storage = new InMemoryCredentialStorage();
		$storage->set_credentials( 'site-1', 'k' );

		return new ImunifyScanner(
			$http,
			$logger,
			$storage,
			new WpTransientJobStore(),
			new FileCollector(),
			'example.com',
			$base
		);
	}

	/**
	 * Builds a temp tree with two .php files for the manifest tests.
	 */
	private function mkdir_tree(): string {
		$root = sys_get_temp_dir() . '/llar-scan-' . uniqid();
		@mkdir( $root, 0755, true ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		file_put_contents( $root . '/a.php', '<?php echo 1;' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		file_put_contents( $root . '/b.php', '<?php echo 2;' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		return $root;
	}

	/**
	 * Recursively removes a directory tree.
	 *
	 * @param string $path Path.
	 */
	private function rm( string $path ): void {
		if ( ! is_dir( $path ) ) {
			return;
		}
		foreach ( scandir( $path ) as $entry ) {
			if ( '.' === $entry || '..' === $entry ) {
				continue;
			}
			$child = $path . '/' . $entry;
			if ( is_dir( $child ) ) {
				$this->rm( $child );
			} else {
				unlink( $child ); // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink
			}
		}
		rmdir( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_rmdir
	}
}
