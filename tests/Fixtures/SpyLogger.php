<?php
/**
 * Spy logger capturing records for assertions.
 *
 * @package Integrum\SecurityScanner\Tests\Fixtures
 */

declare( strict_types = 1 );

namespace Integrum\SecurityScanner\Tests\Fixtures;

use Integrum\SecurityScanner\Contracts\LoggerInterface;

/**
 * Collects every log call so tests can assert what was journaled.
 */
final class SpyLogger implements LoggerInterface {

	/**
	 * Captured records.
	 *
	 * @var array<int, array{level: string, message: string, context: array<string, mixed>}>
	 */
	public array $records = array();

	/**
	 * {@inheritdoc}
	 */
	public function debug( string $message, array $context = array() ): void {
		$this->records[] = array(
			'level'   => 'debug',
			'message' => $message,
			'context' => $context,
		);
	}

	/**
	 * {@inheritdoc}
	 */
	public function error( string $message, array $context = array() ): void {
		$this->records[] = array(
			'level'   => 'error',
			'message' => $message,
			'context' => $context,
		);
	}

	/**
	 * Returns only error-level records.
	 *
	 * @return array<int, array{level: string, message: string, context: array<string, mixed>}>
	 */
	public function errors(): array {
		return array_values(
			array_filter(
				$this->records,
				fn( array $r ): bool => 'error' === $r['level']
			)
		);
	}

	/**
	 * True when an error-level message contains the needle.
	 *
	 * @param string $needle Substring to look for.
	 */
	public function has_error_containing( string $needle ): bool {
		foreach ( $this->errors() as $record ) {
			if ( false !== strpos( $record['message'], $needle ) ) {
				return true;
			}
		}
		return false;
	}
}
