<?php
/**
 * In-memory CredentialStorage for tests.
 *
 * @package Integrum\SecurityScanner\Tests\Fixtures
 */

declare( strict_types = 1 );

namespace Integrum\SecurityScanner\Tests\Fixtures;

use Integrum\SecurityScanner\Contracts\CredentialStorageInterface;

final class InMemoryCredentialStorage implements CredentialStorageInterface {

	private ?string $site_id  = null;
	private ?string $site_key = null;

	public function get_site_id(): ?string {
		return $this->site_id;
	}

	public function get_site_key(): ?string {
		return $this->site_key;
	}

	public function set_credentials( string $site_id, string $site_key ): void {
		$this->site_id  = $site_id;
		$this->site_key = $site_key;
	}

	public function clear_credentials(): void {
		$this->site_id  = null;
		$this->site_key = null;
	}
}
