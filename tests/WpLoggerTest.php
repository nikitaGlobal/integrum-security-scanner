<?php
/**
 * WpLogger gating and redaction tests.
 *
 * @package Integrum\SecurityScanner\Tests
 */

declare( strict_types = 1 );

namespace Integrum\SecurityScanner\Tests;

use Integrum\SecurityScanner\Models\WpLogger;
use Integrum\SecurityScanner\Tests\Fixtures\InMemoryCredentialStorage;
use PHPUnit\Framework\TestCase;

/**
 * Logging follows WP_DEBUG and never leaks credentials.
 */
final class WpLoggerTest extends TestCase {

	/**
	 * Captured log lines.
	 *
	 * @var string[]
	 */
	private array $lines = array();

	protected function setUp(): void {
		$GLOBALS['__llar_filters'] = array();
		$this->lines               = array();
	}

	public function test_logging_is_disabled_when_wp_debug_is_false(): void {
		$logger = $this->make_logger();

		$this->assertFalse( WpLogger::is_enabled() );

		$logger->error( 'boom' );
		$logger->debug( 'trace' );

		$this->assertSame( array(), $this->lines, 'Nothing must be written while WP_DEBUG is off.' );
	}

	public function test_filter_can_force_logging_and_secrets_are_redacted(): void {
		$GLOBALS['__llar_filters'][ WpLogger::ENABLED_FILTER ] = true;

		$storage = new InMemoryCredentialStorage();
		$storage->set_credentials( 'site-id', 'super-secret-key' );

		$logger = $this->make_logger( $storage );

		$this->assertTrue( WpLogger::is_enabled() );

		$logger->error(
			'boom',
			array(
				'site_key' => 'plain-value',
				'detail'   => 'value with super-secret-key inside',
			)
		);

		$this->assertCount( 1, $this->lines );
		$this->assertStringContainsString( 'ERROR boom', $this->lines[0] );
		$this->assertStringContainsString( '[REDACTED]', $this->lines[0] );
		$this->assertStringNotContainsString( 'super-secret-key', $this->lines[0] );
	}

	public function test_redaction_walks_nested_context(): void {
		$GLOBALS['__llar_filters'][ WpLogger::ENABLED_FILTER ] = true;

		$storage = new InMemoryCredentialStorage();
		$storage->set_credentials( 'site-id', 'super-secret-key' );

		$this->make_logger( $storage )->error(
			'boom',
			array(
				'request' => array(
					'headers' => array( 'X-Site-Key' => 'super-secret-key' ),
					'detail'  => 'value with super-secret-key inside',
				),
			)
		);

		$this->assertCount( 1, $this->lines );
		$this->assertStringNotContainsString( 'super-secret-key', $this->lines[0] );
		$this->assertStringContainsString( '[REDACTED]', $this->lines[0] );
	}

	/**
	 * Builds a logger that collects lines instead of calling error_log().
	 *
	 * @param InMemoryCredentialStorage|null $storage Optional credential storage.
	 */
	private function make_logger( ?InMemoryCredentialStorage $storage = null ): WpLogger {
		return new WpLogger(
			$storage,
			function ( string $line ): void {
				$this->lines[] = $line;
			}
		);
	}
}
