<?php
/**
 * PHPUnit bootstrap.
 *
 * Runs the plugin's classes against lightweight WP stubs, no WordPress / no
 * Composer required.
 *
 * @package Integrum\SecurityScanner\Tests
 */

declare( strict_types = 1 );

// Minimal WP function stubs needed by the classes under test.
if ( ! function_exists( 'wp_json_encode' ) ) {
	/**
	 * @param mixed $data Data.
	 */
	function wp_json_encode( $data ): string|false {
		return json_encode( $data );
	}
}

if ( ! function_exists( '__' ) ) {
	/**
	 * Pass-through i18n stub: returns the original string.
	 *
	 * @param string $text   Text.
	 * @param string $domain Domain (unused).
	 */
	// phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed -- WP signature.
	function __( string $text, string $domain = 'default' ): string {
		return $text;
	}
}

if ( ! function_exists( 'apply_filters' ) ) {
	/**
	 * Filter stub: reads the value from $GLOBALS['__llar_filters'].
	 *
	 * @param string $hook  Filter name.
	 * @param mixed  $value Default value.
	 * @param mixed  ...$args Extra arguments (unused).
	 * @return mixed
	 */
	// phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed -- WP signature.
	function apply_filters( string $hook, $value, ...$args ) {
		return $GLOBALS['__llar_filters'][ $hook ] ?? $value;
	}
}

if ( ! function_exists( 'is_email' ) ) {
	/**
	 * Minimal email validation stub.
	 *
	 * @param string $email Email.
	 */
	function is_email( string $email ): bool {
		return false !== filter_var( $email, FILTER_VALIDATE_EMAIL );
	}
}

if ( ! function_exists( '_n' ) ) {
	/**
	 * Pass-through plural i18n stub.
	 *
	 * @param string $single Singular form.
	 * @param string $plural Plural form.
	 * @param int    $number Number.
	 * @param string $domain Domain (unused).
	 */
	// phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed -- WP signature.
	function _n( string $single, string $plural, int $number, string $domain = 'default' ): string {
		return 1 === $number ? $single : $plural;
	}
}

// Array-backed option stubs for the option-backed models (ScanHistoryStorage).
// Tests reset $GLOBALS['__llar_options'] in setUp().
if ( ! function_exists( 'get_option' ) ) {
	/**
	 * Reads a value from the in-memory options table.
	 *
	 * @param string $name Option name.
	 * @param mixed  $default Default when missing.
	 * @return mixed
	 */
	// phpcs:ignore Universal.NamingConventions.NoReservedKeywordParameterNames -- WP signature.
	function get_option( string $name, $default = false ) {
		return \array_key_exists( $name, $GLOBALS['__llar_options'] ?? array() ) ? $GLOBALS['__llar_options'][ $name ] : $default;
	}
}

if ( ! function_exists( 'update_option' ) ) {
	/**
	 * Writes a value to the in-memory options table.
	 *
	 * @param string $name Option name.
	 * @param mixed  $value Value.
	 * @param bool   $autoload Autoload flag (unused).
	 * @return bool
	 */
	// phpcs:ignore Universal.NamingConventions.NoReservedKeywordParameterNames, Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed -- WP signature.
	function update_option( string $name, $value, $autoload = null ): bool {
		$GLOBALS['__llar_options'][ $name ] = $value;
		return true;
	}
}

if ( ! defined( 'HOUR_IN_SECONDS' ) ) {
	define( 'HOUR_IN_SECONDS', 3600 );
}

/**
 * Test clock: overridable via $GLOBALS['__llar_test_now'].
 *
 * @return int Current test time.
 */
function llar_test_now(): int {
	return $GLOBALS['__llar_test_now'] ?? time();
}

// Transients API stubs with real expiry support. The per-job scan state is
// stored in transients with a 1-hour TTL, so the tests must be able to
// simulate the clock running past it.
if ( ! function_exists( 'set_transient' ) ) {
	/**
	 * Emulates the WP Transients API with real expiry support.
	 *
	 * @param string $key   Transient key.
	 * @param mixed  $value Value.
	 * @param int    $ttl   Expiration in seconds (0 = never).
	 * @return bool
	 */
	function set_transient( string $key, $value, int $ttl = 0 ): bool {
		$GLOBALS['__llar_test_transients']       ??= array();
		$GLOBALS['__llar_test_transients'][ $key ] = array(
			'value'   => $value,
			'expires' => $ttl > 0 ? llar_test_now() + $ttl : 0,
		);
		return true;
	}
}

if ( ! function_exists( 'get_transient' ) ) {
	/**
	 * Emulates the WP Transients API with real expiry support.
	 *
	 * @param string $key Transient key.
	 * @return mixed False on miss (like WP).
	 */
	function get_transient( string $key ) {
		$entry = $GLOBALS['__llar_test_transients'][ $key ] ?? null;
		if ( null === $entry ) {
			return false;
		}
		if ( $entry['expires'] > 0 && $entry['expires'] <= llar_test_now() ) {
			return false;
		}
		return $entry['value'];
	}
}

if ( ! function_exists( 'delete_transient' ) ) {
	/**
	 * Emulates transient deletion.
	 *
	 * @param string $key Transient key.
	 * @return bool
	 */
	function delete_transient( string $key ): bool {
		unset( $GLOBALS['__llar_test_transients'][ $key ] );
		return true;
	}
}

$plugin_src = __DIR__ . '/../src/';

/**
 * Simple autoloader:
 *  - Integrum\SecurityScanner\Tests\*  -> tests/
 *  - Integrum\SecurityScanner\*        -> wp-content/plugins/integrum-security-scanner/src/
 *
 * @param string $fqcn Fully-qualified class name.
 */
spl_autoload_register(
	function ( string $fqcn ) use ( $plugin_src ): void {
		$tests_prefix = 'Integrum\\SecurityScanner\\Tests\\';
		if ( 0 === strncmp( $fqcn, $tests_prefix, strlen( $tests_prefix ) ) ) {
			$path = __DIR__ . '/' . str_replace( '\\', '/', substr( $fqcn, strlen( $tests_prefix ) ) ) . '.php';
			if ( is_file( $path ) ) {
				require_once $path;
			}
			return;
		}

		$prefix = 'Integrum\\SecurityScanner\\';
		if ( 0 !== strncmp( $fqcn, $prefix, strlen( $prefix ) ) ) {
			return;
		}
		$path = $plugin_src . str_replace( '\\', '/', substr( $fqcn, strlen( $prefix ) ) ) . '.php';
		if ( is_file( $path ) ) {
			require_once $path;
		}
	}
);
