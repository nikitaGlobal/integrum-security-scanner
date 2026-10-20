<?php
/**
 * Logger backed by PHP/WordPress native `error_log()`.
 *
 * Fully disabled unless `WP_DEBUG` is true, so a production site does not
 * write a record for every HTTP call. When `WP_DEBUG_LOG` is enabled,
 * WordPress routes `error_log()` output to `wp-content/debug.log`; otherwise
 * it lands in the server PHP error log. No custom file is created.
 *
 * @package Integrum\SecurityScanner\Models
 */

declare( strict_types = 1 );

namespace Integrum\SecurityScanner\Models;

use Integrum\SecurityScanner\Contracts\CredentialStorageInterface;
use Integrum\SecurityScanner\Contracts\LoggerInterface;

/**
 * Thin adapter over error_log() with credential redaction.
 */
final class WpLogger implements LoggerInterface {

	/**
	 * Filter that can force logging on (or off) regardless of WP_DEBUG.
	 */
	public const ENABLED_FILTER = 'integrum_security_scanner_logging_enabled';

	/**
	 * Redactor for log context.
	 */
	private CredentialRedactor $redactor;

	/**
	 * Line writer; null means the native error_log().
	 */
	private ?\Closure $writer;

	/**
	 * Constructor.
	 *
	 * @param CredentialStorageInterface|null $storage Optional credentials for value masking.
	 * @param callable|null                   $writer  Optional line writer (tests).
	 */
	public function __construct( ?CredentialStorageInterface $storage = null, ?callable $writer = null ) {
		$this->redactor = new CredentialRedactor( $storage );
		$this->writer   = null !== $writer ? \Closure::fromCallable( $writer ) : null;
	}

	/**
	 * Whether logging is enabled for the current request.
	 *
	 * Follows WP_DEBUG by default; the ENABLED_FILTER hook allows turning
	 * logging on for a temporary production diagnosis (or off entirely).
	 */
	public static function is_enabled(): bool {
		$enabled = defined( 'WP_DEBUG' ) && WP_DEBUG;
		return (bool) apply_filters( self::ENABLED_FILTER, (bool) $enabled );
	}

	/**
	 * {@inheritdoc}
	 */
	public function debug( string $message, array $context = array() ): void {
		$this->log( 'DEBUG', $message, $context );
	}

	/**
	 * {@inheritdoc}
	 */
	public function error( string $message, array $context = array() ): void {
		$this->log( 'ERROR', $message, $context );
	}

	/**
	 * Formats one line and hands it to error_log().
	 *
	 * @param string               $level   Level name.
	 * @param string               $message Message.
	 * @param array<string, mixed> $context Context.
	 */
	private function log( string $level, string $message, array $context ): void {
		if ( ! self::is_enabled() ) {
			return;
		}

		$context = $this->redactor->redact_context( $context );
		$line    = '[' . gmdate( 'Y-m-d H:i:s' ) . '] ' . $level . ' ' . $message;
		if ( array() !== $context ) {
			$encoded = wp_json_encode( $context );
			if ( false !== $encoded ) {
				$line .= ' ' . $encoded;
			}
		}

		if ( null !== $this->writer ) {
			( $this->writer )( $line );
			return;
		}

		error_log( $line ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
	}
}
