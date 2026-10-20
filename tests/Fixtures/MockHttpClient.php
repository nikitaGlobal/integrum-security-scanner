<?php
/**
 * In-memory HTTP client used by tests.
 *
 * @package Integrum\SecurityScanner\Tests\Fixtures
 */

declare( strict_types = 1 );

namespace Integrum\SecurityScanner\Tests\Fixtures;

use Integrum\SecurityScanner\Contracts\HttpClientInterface;
use Integrum\SecurityScanner\Contracts\HttpException;

/**
 * Registers canned responses keyed by "METHOD URL" and replays them.
 *
 * Both request() and upload() consult the same scenario table, so a test can
 * assert the scanner handshake end-to-end (scan/start -> results -> hashes ->
 * upload) by registering a response for each URL.
 */
final class MockHttpClient implements HttpClientInterface {

	/**
	 * Registered scenarios.
	 *
	 * @var array<string, array{code: int, body: array<string, mixed>}>
	 */
	private array $scenarios = array();

	/**
	 * Captured requests in call order.
	 *
	 * @var array<int, array{method: string, url: string, body: mixed, api_key: string|null}>
	 */
	private array $recorded = array();

	/**
	 * Registers a scenario.
	 *
	 * @param string               $method HTTP method.
	 * @param string               $url    URL.
	 * @param int                  $code   HTTP status code.
	 * @param array<string, mixed> $body   Decoded body.
	 */
	public function add_scenario( string $method, string $url, int $code, array $body ): void {
		$this->scenarios[ strtoupper( $method ) . ' ' . $url ] = array(
			'code' => $code,
			'body' => $body,
		);
	}

	/**
	 * {@inheritdoc}
	 *
	 * @throws HttpException When no scenario is registered.
	 */
	public function request( string $method, string $url, array $body = array(), ?string $api_key = null ): array {
		return $this->dispatch( strtoupper( $method ), $url, $body, $api_key );
	}

	/**
	 * {@inheritdoc}
	 *
	 * @throws HttpException When no scenario is registered.
	 */
	public function upload( string $url, string $file_path, string $file_id, ?string $api_key = null ): array {
		return $this->dispatch(
			'POST',
			$url,
			array(
				'file_id' => $file_id,
				'path'    => $file_path,
			),
			$api_key
		);
	}

	/**
	 * Returns every captured request.
	 *
	 * @return array<int, array{method: string, url: string, body: mixed, api_key: string|null}>
	 */
	public function recorded(): array {
		return $this->recorded;
	}

	/**
	 * Shared lookup + recording for request() and upload().
	 *
	 * @param string      $method  HTTP method.
	 * @param string      $url     URL.
	 * @param mixed       $body    Body payload.
	 * @param string|null $api_key Site key.
	 * @return array{code: int, body: array<string, mixed>}
	 *
	 * @throws HttpException When no scenario is registered.
	 */
	private function dispatch( string $method, string $url, $body, ?string $api_key ): array {
		$key = $method . ' ' . $url;

		$this->recorded[] = array(
			'method'  => $method,
			'url'     => $url,
			'body'    => $body,
			'api_key' => $api_key,
		);

		if ( ! isset( $this->scenarios[ $key ] ) ) {
			throw new HttpException( "No scenario registered for $key" );
		}

		return $this->scenarios[ $key ];
	}
}
