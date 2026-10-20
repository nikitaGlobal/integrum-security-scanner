<?php
/**
 * Null Logger for tests.
 *
 * @package Integrum\SecurityScanner\Tests\Fixtures
 */

declare( strict_types = 1 );

namespace Integrum\SecurityScanner\Tests\Fixtures;

use Integrum\SecurityScanner\Contracts\LoggerInterface;

final class NullLogger implements LoggerInterface {

	public function debug( string $message, array $context = array() ): void {
	}

	public function error( string $message, array $context = array() ): void {
	}
}
