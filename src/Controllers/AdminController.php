<?php
/**
 * The single admin page: key, masks, scan button, results.
 *
 * @package Integrum\SecurityScanner\Controllers
 */

declare( strict_types = 1 );

namespace Integrum\SecurityScanner\Controllers;

use Integrum\SecurityScanner\Contracts\CredentialStorageInterface;
use Integrum\SecurityScanner\Contracts\FileCollectorInterface;
use Integrum\SecurityScanner\Contracts\LoggerInterface;
use Integrum\SecurityScanner\Contracts\ScanException;
use Integrum\SecurityScanner\Contracts\ScannerInterface;
use Integrum\SecurityScanner\Models\ScanHistoryStorage;
use Integrum\SecurityScanner\Models\ScanResult;
use Integrum\SecurityScanner\Services\LicensingService;

/**
 * Registers the menu, renders the page, handles the two POST forms
 * (Get key / Start scan) and exposes AJAX actions for polling.
 */
final class AdminController {

	private const SLUG            = 'integrum-security-scanner';
	private const NONCE_GET_KEY   = 'integrum_security_scanner_get_key';
	private const NONCE_START     = 'integrum_security_scanner_start_scan';
	private const NONCE_POLL      = 'integrum_security_scanner_poll';
	private const CAPABILITY      = 'manage_options';
	private const OPTION_SETTINGS = 'integrum_security_scanner_scan_settings';

	/**
	 * Directory slugs checked by default (before anything is saved).
	 *
	 * @var string[]
	 */
	private const DEFAULT_DIRECTORIES = array( 'root', 'wp-admin', 'wp-includes', 'wp-content' );

	/**
	 * Constructor.
	 *
	 * @param ScannerInterface           $scanner  Scanner.
	 * @param CredentialStorageInterface $storage  Storage.
	 * @param LicensingService           $licensing Licensing service.
	 * @param LoggerInterface            $logger   Logger.
	 * @param FileCollectorInterface     $file_collector Candidate file list builder (scan preview).
	 * @param ScanHistoryStorage|null    $history  Finished-run history (defaults to a new store).
	 */
	public function __construct(
		private ScannerInterface $scanner,
		private CredentialStorageInterface $storage,
		private LicensingService $licensing,
		private LoggerInterface $logger,
		private FileCollectorInterface $file_collector,
		private ?ScanHistoryStorage $history = null
	) {
		$this->history = $this->history ?? new ScanHistoryStorage();
	}

	/**
	 * Registers WordPress hooks.
	 */
	public function register(): void {
		add_action( 'admin_menu', array( $this, 'add_menu' ) );
		add_action( 'admin_init', array( $this, 'handle_post' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue' ) );

		add_action( 'wp_ajax_integrum_security_scanner_status', array( $this, 'ajax_status' ) );
		add_action( 'wp_ajax_integrum_security_scanner_stop', array( $this, 'ajax_stop' ) );
		add_action( 'wp_ajax_integrum_security_scanner_results', array( $this, 'ajax_results' ) );
		add_action( 'wp_ajax_integrum_security_scanner_preview', array( $this, 'ajax_preview' ) );
		add_action( 'wp_ajax_integrum_security_scanner_dirchildren', array( $this, 'ajax_dirchildren' ) );
		add_action( 'wp_ajax_integrum_security_scanner_history', array( $this, 'ajax_history' ) );
	}

	/**
	 * Adds the admin menu entry.
	 */
	public function add_menu(): void {
		add_menu_page(
			__( 'Integrum Security Scanner', 'integrum-security-scanner' ),
			__( 'Site Security', 'integrum-security-scanner' ),
			self::CAPABILITY,
			self::SLUG,
			array( $this, 'render' ),
			'dashicons-shield',
			80
		);
	}

	/**
	 * Enqueues assets on the plugin page only.
	 *
	 * @param string $hook Current admin page hook.
	 */
	public function enqueue( string $hook ): void {
		if ( 'toplevel_page_' . self::SLUG !== $hook ) {
			return;
		}

		// Pre-built Tailwind stylesheet: utilities are scoped under
		// #integrum-security-scanner-app and preflight is disabled so the WP admin
		// chrome is never affected. Rebuild with:
		// node node_modules/tailwindcss/lib/cli.js -i tailwind-src.css -o wp-content/plugins/integrum-security-scanner/assets/css/tailwind.build.css --minify
		// admin.js is an esbuild bundle of the ES modules in assets/js/src/.
		// Rebuild with: npm run build:js (from the dev workspace root).
		// Asset versions use filemtime so every code change busts the browser
		// cache (a stale admin.js otherwise leaves the file tree empty). Built
		// assets are gitignored, so fall back to the plugin version until the
		// missing file is rebuilt to avoid a filemtime() stat warning.
		$css_path = INTEGRUM_SECURITY_SCANNER_DIR . 'assets/css/tailwind.build.css';
		$js_path  = INTEGRUM_SECURITY_SCANNER_DIR . 'assets/js/admin.js';
		$css_ver  = file_exists( $css_path ) ? (string) filemtime( $css_path ) : INTEGRUM_SECURITY_SCANNER_VERSION;
		$js_ver   = file_exists( $js_path ) ? (string) filemtime( $js_path ) : INTEGRUM_SECURITY_SCANNER_VERSION;

		wp_enqueue_style(
			'integrum-security-scanner-admin',
			INTEGRUM_SECURITY_SCANNER_URL . 'assets/css/tailwind.build.css',
			array(),
			$css_ver
		);

		wp_enqueue_script(
			'integrum-security-scanner-admin',
			INTEGRUM_SECURITY_SCANNER_URL . 'assets/js/admin.js',
			array(),
			$js_ver,
			true
		);

		wp_localize_script(
			'integrum-security-scanner-admin',
			'llarSecurityScanner',
			array(
				'ajaxUrl' => admin_url( 'admin-ajax.php' ),
				'nonce'   => wp_create_nonce( self::NONCE_POLL ),
				'i18n'    => array(
					'error'          => __( 'Scan failed. Please try again.', 'integrum-security-scanner' ),
					'retrying'       => __( 'Connection lost, retrying…', 'integrum-security-scanner' ),
					'saveKey'        => __( 'Save key', 'integrum-security-scanner' ),
					'register'       => __( 'Register', 'integrum-security-scanner' ),
					'showKey'        => __( 'Show site key', 'integrum-security-scanner' ),
					'hideKey'        => __( 'Hide site key', 'integrum-security-scanner' ),
					'stopped'        => __( 'Scan stopped.', 'integrum-security-scanner' ),
					'stopping'       => __( 'Stopping…', 'integrum-security-scanner' ),
					'file'           => __( 'file', 'integrum-security-scanner' ),
					'files'          => __( 'files', 'integrum-security-scanner' ),
					'scanCompleted'  => __( 'Scan completed: {scanned} files scanned, {suspicious} suspicious.', 'integrum-security-scanner' ),
					'scanFailed'     => __( 'Scan failed.', 'integrum-security-scanner' ),
					'historyLoading' => __( 'Loading…', 'integrum-security-scanner' ),
					'historyClean'   => __( 'No problem files in this scan.', 'integrum-security-scanner' ),
					'statusLabels'   => array(
						'infected'   => __( 'infected', 'integrum-security-scanner' ),
						'suspicious' => __( 'suspicious', 'integrum-security-scanner' ),
						'error'      => __( 'error', 'integrum-security-scanner' ),
					),
					'statusHints'    => array(
						'infected'   => __( 'Malicious code detected. Back up your site, then replace this file with a clean copy from the original source and check other recently modified files.', 'integrum-security-scanner' ),
						'suspicious' => __( 'Potentially dangerous code detected. Review the file content before deleting anything — obfuscated code can be a false positive.', 'integrum-security-scanner' ),
						'error'      => __( 'The file could not be scanned. Check the server logs and scan again, or review the file manually.', 'integrum-security-scanner' ),
					),
					'severity'       => array(
						'critical' => __( 'critical', 'integrum-security-scanner' ),
						'high'     => __( 'high', 'integrum-security-scanner' ),
						'medium'   => __( 'medium', 'integrum-security-scanner' ),
						'low'      => __( 'low', 'integrum-security-scanner' ),
						'info'     => __( 'info', 'integrum-security-scanner' ),
					),
					'severityHints'  => array(
						'critical' => __( 'Critical: the file almost certainly contains malware. Replace it with a clean copy immediately.', 'integrum-security-scanner' ),
						'high'     => __( 'High: likely malware. Replace the file with a clean copy from a trusted source.', 'integrum-security-scanner' ),
						'medium'   => __( 'Medium: suspicious code constructs found. Review the file and clean it up if needed.', 'integrum-security-scanner' ),
						'low'      => __( 'Low: minor concerns only. Review the file when convenient.', 'integrum-security-scanner' ),
						'info'     => __( 'Informational finding. No action needed unless it keeps reappearing.', 'integrum-security-scanner' ),
					),
				),
			)
		);
	}

	/**
	 * Handles the two POST forms (Get key / Start scan) using admin referer checks.
	 */
	public function handle_post(): void {
		$action = '';
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- nonce verified inside each handler.
		if ( isset( $_POST['integrum_security_scanner_action'] ) ) {
			$action = sanitize_text_field( wp_unslash( $_POST['integrum_security_scanner_action'] ) );
		}
		// phpcs:enable WordPress.Security.NonceVerification.Missing

		if ( '' === $action ) {
			return;
		}

		if ( ! current_user_can( self::CAPABILITY ) ) {
			wp_die( esc_html__( 'Insufficient permissions.', 'integrum-security-scanner' ) );
		}

		switch ( $action ) {
			case 'get_key':
				$this->handle_get_key();
				break;
			case 'start_scan':
				$this->handle_start_scan();
				break;
		}
	}

	/**
	 * Handles the Get key form.
	 */
	private function handle_get_key(): void {
		check_admin_referer( self::NONCE_GET_KEY );

		$manual_key = isset( $_POST['integrum_security_scanner_key'] ) ? sanitize_text_field( wp_unslash( $_POST['integrum_security_scanner_key'] ) ) : '';

		// When user provides a key manually, store it directly without API call.
		if ( '' !== $manual_key ) {
			$existing = $this->storage->get_site_id();
			$this->storage->set_credentials( $existing ?? 'manual', $manual_key );

			$this->redirect(
				array(
					'type'    => 'success',
					'message' => __( 'Site key saved.', 'integrum-security-scanner' ),
					'scope'   => 'connection',
				)
			);
			return;
		}

		$terms_accepted = isset( $_POST['integrum_security_scanner_terms'] ) && '1' === sanitize_text_field( wp_unslash( $_POST['integrum_security_scanner_terms'] ) );
		if ( ! $terms_accepted ) {
			$this->redirect(
				array(
					'type'    => 'error',
					'message' => __( 'You must agree to the Terms of Service and Malware Scanning Terms before registering.', 'integrum-security-scanner' ),
					'scope'   => 'connection',
				)
			);
			return;
		}

		$domain = (string) apply_filters( 'integrum_security_scanner_site_domain', '' );
		$email  = isset( $_POST['integrum_security_scanner_email'] ) ? sanitize_email( wp_unslash( $_POST['integrum_security_scanner_email'] ) ) : '';

		$notice          = $this->licensing->register( (string) $domain, $email );
		$notice['scope'] = 'connection';
		$this->redirect( $notice );
	}

	/**
	 * Handles the Start scan form.
	 */
	private function handle_start_scan(): void {
		check_admin_referer( self::NONCE_START );

		$allowed = $this->directory_options();

		$dir_slugs     = $this->sanitize_directory_slugs( $_POST['integrum_security_scanner_directories'] ?? array(), $allowed ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- sanitised inside sanitize_directory_slugs().
		$include_masks = $this->parse_masks( $_POST['integrum_security_scanner_include'] ?? '' ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- sanitised inside parse_masks().
		$exclude_masks = $this->parse_masks( $_POST['integrum_security_scanner_exclude'] ?? '' ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- sanitised inside parse_masks().
		$tree_flags    = $this->tree_flags_from_post();

		// Persist the user's selections so the form keeps its state across reloads
		// (even when the scan fails, e.g. quota exceeded — the user can retry).
		$this->store_scan_settings(
			$dir_slugs,
			isset( $_POST['integrum_security_scanner_include'] ) ? sanitize_text_field( wp_unslash( $_POST['integrum_security_scanner_include'] ) ) : '', // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- unslashed above.
			isset( $_POST['integrum_security_scanner_exclude'] ) ? sanitize_text_field( wp_unslash( $_POST['integrum_security_scanner_exclude'] ) ) : '', // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- unslashed above.
			$tree_flags
		);

		// Explicit tree flags are authoritative; the flat directory slugs are
		// the legacy/no-JS path.
		if ( array() !== $tree_flags ) {
			$scope         = $this->scope_from_flags( $tree_flags, $include_masks, $exclude_masks );
			$directories   = $scope[0];
			$include_masks = $scope[1];
			$exclude_masks = $scope[2];

			if ( array() === $directories ) {
				$this->redirect(
					array(
						'type'    => 'error',
						'message' => __( 'Select at least one directory to scan.', 'integrum-security-scanner' ),
						'scope'   => 'scan',
					)
				);
				return;
			}
		} else {
			$directories = $this->resolve_scan_directories( $dir_slugs, $allowed );
		}

		try {
			$job_id = $this->scanner->start_scan( $directories, $include_masks, $exclude_masks );
		} catch ( ScanException $e ) {
			$this->logger->error(
				'scan start failed',
				array(
					'message' => $e->getMessage(),
					'code'    => $e->getCode(),
				)
			);

			$is_key_error = 401 === $e->getCode();
			$real_message = $e->getMessage();
			$message      = $is_key_error
				? __( 'The site key is missing or was rejected. Use the Connection form above to obtain a new key, then start the scan again.', 'integrum-security-scanner' )
				: ( '' !== $real_message ? $real_message : __( 'Could not start the scan. Please try again in a moment.', 'integrum-security-scanner' ) );

			$this->redirect(
				array(
					'type'    => 'error',
					'message' => $message,
					'scope'   => 'scan',
				)
			);
			return;
		}

		set_transient( 'integrum_security_scanner_active_job', $job_id, HOUR_IN_SECONDS );
		// One-shot marker consumed by render() on the FIRST page load after the
		// PRG redirect. It is NOT a persistent "scan in progress" flag: once
		// consumed, a page reload no longer surfaces a running scan, so the UI
		// returns to idle and the scan is not silently resumed by the poller.
		set_transient( 'integrum_security_scanner_started_job', $job_id, 5 * MINUTE_IN_SECONDS );

		$this->redirect(
			array(
				'type'    => 'success',
				'message' => __( 'Scan started. Do not close this page until it completes.', 'integrum-security-scanner' ),
				'scope'   => 'scan',
			)
		);
	}

	/**
	 * AJAX: returns current scan status for the active job.
	 */
	public function ajax_status(): void {
		check_ajax_referer( self::NONCE_POLL, 'nonce' );

		if ( ! current_user_can( self::CAPABILITY ) ) {
			wp_send_json_error( array( 'message' => 'forbidden' ), 403 );
		}

		$job_id = '';
		if ( isset( $_POST['job_id'] ) ) {
			$job_id = sanitize_text_field( wp_unslash( $_POST['job_id'] ) );
		} elseif ( get_transient( 'integrum_security_scanner_active_job' ) ) {
			$job_id = (string) get_transient( 'integrum_security_scanner_active_job' );
		}

		if ( '' === $job_id ) {
			wp_send_json_error( array( 'message' => 'no job' ) );
		}

		try {
			$status = $this->scanner->get_status( $job_id );
		} catch ( ScanException $e ) {
			wp_send_json_error( array( 'message' => $e->getMessage() ) );
		}

		if ( in_array( $status['status'], array( 'completed', 'done', 'failed' ), true ) ) {
			delete_transient( 'integrum_security_scanner_active_job' );

			// Archive the run once, at the moment completion is first observed.
			// Failed scans are not archived: an empty "0 problems" row would read
			// as a clean scan. record() is idempotent per job, so a repeat poll
			// (or the results fetch racing it) cannot duplicate the entry.
			if ( in_array( $status['status'], array( 'completed', 'done' ), true ) ) {
				$this->record_history( $job_id, $status );
			}
		} else {
			// Keep the job pointer alive while the page keeps polling: long
			// scans outlive the 1-hour transient TTL, and losing the job id
			// here would orphan a still-running scan.
			set_transient( 'integrum_security_scanner_active_job', $job_id, HOUR_IN_SECONDS );
		}

		wp_send_json_success( $status );
	}

	/**
	 * AJAX: stops the active scan by clearing the active job transient.
	 *
	 * The Imunify Connect API has no "cancel" endpoint for a running job; the
	 * server-side scan simply stops being polled and will expire on its own.
	 * We clear the local active-job marker so the poller stops and the UI
	 * returns to the idle state.
	 */
	public function ajax_stop(): void {
		check_ajax_referer( self::NONCE_POLL, 'nonce' );

		if ( ! current_user_can( self::CAPABILITY ) ) {
			wp_send_json_error( array( 'message' => 'forbidden' ), 403 );
		}

		delete_transient( 'integrum_security_scanner_active_job' );

		wp_send_json_success( array( 'status' => 'stopped' ) );
	}

	/**
	 * AJAX: returns the finished-scan history (newest first) for the history
	 * table: the per-run problem-file tree is fetched lazily from here too.
	 */
	public function ajax_history(): void {
		check_ajax_referer( self::NONCE_POLL, 'nonce' );

		if ( ! current_user_can( self::CAPABILITY ) ) {
			wp_send_json_error( array( 'message' => 'forbidden' ), 403 );
		}

		wp_send_json_success( array( 'runs' => $this->history_rows() ) );
	}

	/**
	 * Fetches the finished run's verdicts and archives it. Best-effort: a
	 * failure here must never break the status poll response the UI waits on.
	 *
	 * The scanned total comes from the status counters (completed/total), not
	 * from counting result rows: /results can omit clean files or list nothing
	 * at all once every action was resolved server-side, which archived real
	 * runs as "0 files scanned".
	 *
	 * @param string               $job_id Job id.
	 * @param array<string, mixed> $status Last status payload (completed/total counters).
	 */
	private function record_history( string $job_id, array $status = array() ): void {
		try {
			$results = $this->scanner->get_results( $job_id );
		} catch ( ScanException $e ) {
			return;
		}

		$scanned = max( (int) ( $status['completed'] ?? 0 ), (int) ( $status['total'] ?? 0 ) );

		$this->history->record( $job_id, $results, null, $scanned > 0 ? $scanned : null );
	}

	/**
	 * History rows for both the initial page render and the AJAX refresh:
	 * storage records plus the display-ready date string.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	private function history_rows(): array {
		$rows = array();
		foreach ( $this->history->all() as $run ) {
			$rows[] = array(
				'job_id'   => $run['job_id'],
				'date'     => $this->format_history_date( $run['finished_at'] ),
				'problems' => $run['problems'],
				'scanned'  => $run['scanned'],
				'files'    => $run['files'],
			);
		}
		return $rows;
	}

	/**
	 * Renders a run's completion timestamp in the site timezone and locale.
	 *
	 * @param int $ts Unix timestamp (UTC).
	 */
	private function format_history_date( int $ts ): string {
		return date_i18n( 'j M Y, H:i', $ts + (int) ( (float) get_option( 'gmt_offset' ) * HOUR_IN_SECONDS ) );
	}

	/**
	 * AJAX: returns scan results for a job.
	 */
	public function ajax_results(): void {
		check_ajax_referer( self::NONCE_POLL, 'nonce' );

		if ( ! current_user_can( self::CAPABILITY ) ) {
			wp_send_json_error( array( 'message' => 'forbidden' ), 403 );
		}

		// TODO(dry): this job_id resolution block is duplicated in ajax_status();
		// extract a private resolve_job_id() helper returning `?string`.
		$job_id = '';
		if ( isset( $_POST['job_id'] ) ) {
			$job_id = sanitize_text_field( wp_unslash( $_POST['job_id'] ) );
		} elseif ( get_transient( 'integrum_security_scanner_active_job' ) ) {
			$job_id = (string) get_transient( 'integrum_security_scanner_active_job' );
		}

		if ( '' === $job_id ) {
			wp_send_json_error( array( 'message' => 'no job' ) );
		}

		try {
			$results = $this->scanner->get_results( $job_id );
		} catch ( ScanException $e ) {
			wp_send_json_error( array( 'message' => $e->getMessage() ) );
		}

		wp_send_json_success( array( 'results' => $this->serialize_results( $results ) ) );
	}

	/**
	 * AJAX: returns the child directories of a tree node (lazy loading).
	 */
	public function ajax_dirchildren(): void {
		check_ajax_referer( self::NONCE_POLL, 'nonce' );

		if ( ! current_user_can( self::CAPABILITY ) ) {
			wp_send_json_error( array( 'message' => 'forbidden' ), 403 );
		}

		$rel = isset( $_POST['rel'] ) ? sanitize_text_field( wp_unslash( $_POST['rel'] ) ) : '';
		if ( null === $this->validate_rel_dir( $rel ) ) {
			wp_send_json_error( array( 'message' => 'invalid dir' ) );
		}

		wp_send_json_success( array( 'children' => $this->dir_children_data( $rel ) ) );
	}

	/**
	 * AJAX: returns the file tree preview for the current scan form selections.
	 *
	 * Uses the same FileCollector + mask semantics as a real scan, so the tree
	 * shows exactly what would be scanned before the user starts a job. When
	 * explicit directory-tree flags are posted they are authoritative; the
	 * plain directory slugs are the legacy/no-JS fallback.
	 */
	public function ajax_preview(): void {
		check_ajax_referer( self::NONCE_POLL, 'nonce' );

		if ( ! current_user_can( self::CAPABILITY ) ) {
			wp_send_json_error( array( 'message' => 'forbidden' ), 403 );
		}

		$allowed = $this->directory_options();
		$include = $this->parse_masks( $_POST['integrum_security_scanner_include'] ?? '' ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- sanitised inside parse_masks().
		$exclude = $this->parse_masks( $_POST['integrum_security_scanner_exclude'] ?? '' ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- sanitised inside parse_masks().
		$flags   = $this->tree_flags_from_post();

		if ( array() !== $flags ) {
			$scope       = $this->scope_from_flags( $flags, $include, $exclude );
			$directories = $scope[0];
			$exclude     = $scope[2];
		} else {
			$dir_slugs   = $this->sanitize_directory_slugs( $_POST['integrum_security_scanner_directories'] ?? array(), $allowed ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- sanitised inside sanitize_directory_slugs().
			$directories = $this->resolve_scan_directories( $dir_slugs, $allowed );
		}

		$files = $this->file_collector->collect( $directories, $include, $exclude, $this->site_root() );

		wp_send_json_success(
			array(
				'files' => $files,
				'total' => count( $files ),
			)
		);
	}

	/**
	 * Renders the admin page.
	 */
	public function render(): void {
		if ( ! current_user_can( self::CAPABILITY ) ) {
			return;
		}

		$site_id  = $this->storage->get_site_id();
		$site_key = $this->storage->get_site_key();
		$has_key  = null !== $site_key && '' !== $site_key;
		// The job id shown to the UI comes ONLY from the one-shot started_job
		// transient, so reloading the page (or opening it fresh) does not pick
		// up a previously started scan and resume polling. The scan keeps running
		// server-side while the original tab polls; a reload simply returns the
		// UI to idle rather than silently continuing.
		$job_id      = $this->consume_started_job();
		$notice      = $this->consume_notice();
		$dir_options = $this->directory_options();
		$settings    = $this->load_scan_settings();

		// Directory tree: root node + first level rendered server-side so the
		// top-level checkboxes exist without JS; deeper levels load lazily.
		$tree_flags = $settings['tree'];
		$tree_rows  = $this->dir_children_data( '' );
		foreach ( $tree_rows as &$row ) {
			$row['checked'] = ! $this->tree_eff_off( $row['rel'], $tree_flags );
		}
		unset( $row );
		$tree_root_on = ! $this->tree_eff_off( '', $tree_flags );

		// Finished runs for the history table at the bottom of the page.
		$history_rows = $this->history_rows();

		require INTEGRUM_SECURITY_SCANNER_DIR . 'src/Views/page.php';
	}

	/**
	 * Returns the sanitised list of selected directory slugs.
	 *
	 * @param mixed                $raw    Raw POST value.
	 * @param array<string,string> $allowed Valid slug => path map.
	 * @return string[] Directory slugs (validated against the allowed map).
	 */
	private function sanitize_directory_slugs( $raw, array $allowed ): array {
		if ( ! is_array( $raw ) ) {
			return array();
		}

		$out = array();
		foreach ( $raw as $key ) {
			$key = sanitize_text_field( wp_unslash( $key ) );
			if ( isset( $allowed[ $key ] ) ) {
				$out[] = $key;
			}
		}

		return array_values( array_unique( $out ) );
	}

	/**
	 * Maps validated slugs to paths, falling back to the site root when the
	 * selection is empty (same rule for a real scan and for the preview).
	 *
	 * @param string[]             $slugs   Directory slugs.
	 * @param array<string,string> $allowed Valid slug => path map.
	 * @return string[] Absolute paths.
	 */
	private function resolve_scan_directories( array $slugs, array $allowed ): array {
		$directories = $this->slugs_to_paths( $slugs, $allowed );
		if ( array() === $directories ) {
			$directories = array( $this->site_root() );
		}

		return $directories;
	}

	/**
	 * Maps validated directory slugs back to absolute paths.
	 *
	 * @param string[]             $slugs   Directory slugs.
	 * @param array<string,string> $allowed Valid slug => path map.
	 * @return string[] Absolute paths.
	 */
	private function slugs_to_paths( array $slugs, array $allowed ): array {
		$out = array();
		foreach ( $slugs as $slug ) {
			if ( isset( $allowed[ $slug ] ) ) {
				$out[] = $allowed[ $slug ];
			}
		}

		return array_values( array_unique( $out ) );
	}

	/**
	 * Persists the scan form selections so they survive page reloads.
	 *
	 * @param string[]           $dir_slugs     Selected directory slugs.
	 * @param string             $include_masks Include masks raw string.
	 * @param string             $exclude_masks Exclude masks raw string.
	 * @param array<string,bool> $tree_flags Explicit directory-tree toggles (rel path => checked).
	 */
	private function store_scan_settings( array $dir_slugs, string $include_masks, string $exclude_masks, array $tree_flags ): void {
		update_option(
			self::OPTION_SETTINGS,
			array(
				'directories' => array_values( $dir_slugs ),
				'include'     => $include_masks,
				'exclude'     => $exclude_masks,
				'tree'        => $tree_flags,
			),
			false
		);
	}

	/**
	 * Loads the persisted scan form selections, with sane defaults.
	 *
	 * @return array{directories: string[], include: string, exclude: string, tree: array<string,bool>}
	 */
	private function load_scan_settings(): array {
		$saved = get_option( self::OPTION_SETTINGS );

		if ( ! is_array( $saved ) ) {
			return array(
				'directories' => self::DEFAULT_DIRECTORIES,
				'include'     => '',
				'exclude'     => '',
				'tree'        => array(),
			);
		}

		$dirs = is_array( $saved['directories'] ?? null ) ? array_map( 'strval', $saved['directories'] ) : self::DEFAULT_DIRECTORIES;

		$tree = array();
		if ( is_array( $saved['tree'] ?? null ) ) {
			foreach ( $saved['tree'] as $rel => $on ) {
				$rel = is_string( $rel ) ? trim( str_replace( '\\', '/', $rel ), '/' ) : '';
				if ( '' === $rel || null !== $this->validate_rel_dir( $rel ) ) {
					$tree[ $rel ] = (bool) $on;
				}
			}
		}

		return array(
			'directories' => array() === $dirs ? self::DEFAULT_DIRECTORIES : array_values( $dirs ),
			'include'     => is_string( $saved['include'] ?? null ) ? (string) $saved['include'] : '',
			'exclude'     => is_string( $saved['exclude'] ?? null ) ? (string) $saved['exclude'] : '',
			'tree'        => $tree,
		);
	}

	/**
	 * Parses a comma/newline separated mask string into a list.
	 *
	 * @param mixed $raw Raw value.
	 * @return string[]
	 */
	private function parse_masks( $raw ): array {
		$raw   = is_string( $raw ) ? wp_unslash( $raw ) : '';
		$parts = preg_split( '/[\r\n,]+/', $raw );
		$parts = false === $parts ? array() : $parts;
		$parts = array_map( 'sanitize_text_field', $parts );

		return array_values( array_filter( $parts, 'strlen' ) );
	}

	/**
	 * Maps ScanResult[] to a plain JSON-serialisable array.
	 *
	 * @param ScanResult[] $results Results.
	 * @return array<int, array<string, mixed>>
	 */
	private function serialize_results( array $results ): array {
		$out = array();
		foreach ( $results as $r ) {
			$out[] = array(
				'file_path'   => $r->file_path,
				'status'      => $r->status,
				'threat_type' => $r->threat_type,
				'severity'    => $r->severity,
				'scanned_at'  => $r->scanned_at,
				'detail'      => $r->detail,
			);
		}

		return $out;
	}

	/**
	 * Validates a tree-node relative path and returns its absolute path.
	 *
	 * The path must resolve inside the site root (realpath containment) and be
	 * a directory; '' maps to the site root itself. Returns null for anything
	 * else.
	 *
	 * @param string $rel Relative path ('' = site root).
	 * @return string|null Absolute path, or null when invalid.
	 */
	private function validate_rel_dir( string $rel ): ?string {
		$root = realpath( $this->site_root() );
		if ( false === $root || ! is_string( $root ) ) {
			$root = $this->site_root();
		}

		$rel = trim( str_replace( '\\', '/', $rel ), '/' );
		if ( '' === $rel ) {
			return $root;
		}

		$parts = array_filter( explode( '/', $rel ), 'strlen' );
		foreach ( $parts as $part ) {
			if ( '.' === $part || '..' === $part ) {
				return null;
			}
		}

		$real = realpath( $root . '/' . implode( '/', $parts ) );
		if ( false === $real || ! is_string( $real ) ) {
			return null;
		}

		if ( $real !== $root && 0 !== strpos( $real, $root . DIRECTORY_SEPARATOR ) ) {
			return null;
		}

		return is_dir( $real ) ? $real : null;
	}

	/**
	 * Lists immediate child directories, including dot-prefixed ones.
	 *
	 * Glob() skips hidden entries on Unix; scandir() does not.
	 *
	 * @param string $abs Absolute directory path.
	 * @return string[] Absolute child directory paths.
	 */
	private function list_child_directories( string $abs ): array {
		if ( ! is_dir( $abs ) ) {
			return array();
		}

		$entries = scandir( $abs );
		if ( false === $entries ) {
			return array();
		}

		$out = array();
		foreach ( $entries as $entry ) {
			if ( '.' === $entry || '..' === $entry ) {
				continue;
			}
			$path = $abs . DIRECTORY_SEPARATOR . $entry;
			if ( is_dir( $path ) ) {
				$out[] = $path;
			}
		}

		return $out;
	}

	/**
	 * True when $abs has at least one child directory (including dot-prefixed).
	 *
	 * @param string $abs Absolute directory path.
	 */
	private function directory_has_child_dirs( string $abs ): bool {
		return array() !== $this->list_child_directories( $abs );
	}

	/**
	 * Lists the child directories of a tree node for the selector UI.
	 *
	 * @param string $rel Relative parent path ('' = site root).
	 * @return array<int, array{rel: string, name: string, slug: string, has_children: bool}>
	 */
	private function dir_children_data( string $rel ): array {
		$abs = $this->validate_rel_dir( $rel );
		if ( null === $abs ) {
			return array();
		}

		$options = $this->directory_options();
		$rows    = array();

		foreach ( $this->list_child_directories( $abs ) as $path ) {
			$slug = array_search( $path, $options, true );

			$rows[] = array(
				'rel'          => '' === $rel ? basename( $path ) : $rel . '/' . basename( $path ),
				'name'         => basename( $path ),
				'slug'         => false !== $slug ? (string) $slug : '',
				'has_children' => $this->directory_has_child_dirs( $path ),
			);
		}

		usort( $rows, static fn( array $a, array $b ): int => strcasecmp( $a['name'], $b['name'] ) );

		return $rows;
	}

	/**
	 * Reads the explicit directory-tree toggles from the POSTed form.
	 *
	 * @return array<string,bool> Map of validated rel path => checked.
	 */
	private function tree_flags_from_post(): array {
		$flags = array();

		foreach ( array(
			'on'  => true,
			'off' => false,
		) as $key => $value ) {
			$raw = isset( $_POST[ 'integrum_security_scanner_tree_' . $key ] ) ? $_POST[ 'integrum_security_scanner_tree_' . $key ] : array(); // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- nonce verified by the caller; value sanitised/validated below.
			if ( ! is_array( $raw ) ) {
				continue;
			}

			foreach ( $raw as $rel ) {
				$rel  = sanitize_text_field( wp_unslash( $rel ) );
				$norm = trim( str_replace( '\\', '/', $rel ), '/' );

				if ( '' === $norm ) {
					$flags[''] = $value;
					continue;
				}

				if ( null !== $this->validate_rel_dir( $norm ) ) {
					$flags[ $norm ] = $value;
				}
			}
		}

		return $flags;
	}

	/**
	 * Effective checked state of a node: the nearest explicit flag wins
	 * (self first, then ancestors); default is checked.
	 */
	private function tree_eff_off( string $rel, array $flags ): bool {
		$segs = array_filter( explode( '/', trim( $rel, '/' ) ), 'strlen' );

		for ( $i = count( $segs ); $i >= 0; $i-- ) {
			$prefix = implode( '/', array_slice( $segs, 0, $i ) );
			if ( array_key_exists( $prefix, $flags ) ) {
					return false === $flags[ $prefix ];
			}
		}

		return false;
	}

	/**
	 * Computes the scan scope (directories + derived exclude masks) from the
	 * explicit tree toggles.
	 *
	 * Model: a checked folder means "scan this whole subtree"; an unchecked
	 * folder inside a scanned subtree is expressed as an exclude mask. When the
	 * site root itself is off, only explicitly re-checked subtrees are scanned.
	 *
	 * @param array<string,bool> $flags         Explicit toggles.
	 * @param string[]           $include_masks Include masks.
	 * @param string[]           $exclude_masks Exclude masks.
	 * @return array{0: string[], 1: string[], 2: string[]} [directories, include, exclude]
	 */
	private function scope_from_flags( array $flags, array $include_masks, array $exclude_masks ): array {
		$dirs  = array();
		$extra = array();
		$this->scope_walk( '', $flags, $dirs, $extra );

		return array(
			array_values( array_unique( $dirs ) ),
			$include_masks,
			array_values( array_unique( array_merge( $exclude_masks, $extra ) ) ),
		);
	}

	/**
	 * Recursive worker for scope_from_flags().
	 */
	private function scope_walk( string $rel, array $flags, array &$dirs, array &$extra ): void {
		$abs = $this->validate_rel_dir( $rel );
		if ( null === $abs ) {
			return;
		}

		if ( ! $this->tree_eff_off( $rel, $flags ) ) {
			// Node effectively ON: scan it wholesale, minus maximal OFF flags below.
			$dirs[] = $abs;
			foreach ( $this->maximal_false_below( $rel, $flags ) as $off ) {
				$extra[] = $off . '/**';
			}
			return;
		}

		// Node OFF: descend only along branches that contain explicit ON flags.
		foreach ( $this->list_child_directories( $abs ) as $child ) {
			$child_rel = '' === $rel ? basename( $child ) : $rel . '/' . basename( $child );
			if ( $this->tree_eff_off( $child_rel, $flags ) && ! $this->has_true_below( $child_rel, $flags ) ) {
				continue;
			}
			$this->scope_walk( $child_rel, $flags, $dirs, $extra );
		}
	}

	/**
	 * Returns the unchecked flags strictly below $rel that are not already
	 * covered by a closer unchecked ancestor (maximal ones).
	 *
	 * @return string[]
	 */
	private function maximal_false_below( string $rel, array $flags ): array {
		$out = array();

		foreach ( $flags as $key => $on ) {
			if ( true === $on || ! $this->is_strictly_below( $key, $rel ) ) {
				continue;
			}

			$covered = false;
			foreach ( $flags as $anc => $anc_on ) {
				if ( true === $anc_on || $anc === $key || ! $this->is_strictly_below( $anc, $rel ) ) {
					continue;
				}
				if ( 0 === strpos( $key, $anc . '/' ) ) {
					$covered = true;
					break;
				}
			}

			if ( ! $covered ) {
				$out[] = $key;
			}
		}

		return $out;
	}

	/**
	 * True when any explicitly-checked flag exists strictly below $rel.
	 */
	private function has_true_below( string $rel, array $flags ): bool {
		foreach ( $flags as $key => $on ) {
			if ( true === $on && $this->is_strictly_below( $key, $rel ) ) {
					return true;
			}
		}
		return false;
	}

	/**
	 * True when $key is a strict descendant of $rel ('' = site root).
	 */
	private function is_strictly_below( string $key, string $rel ): bool {
		if ( '' === $rel ) {
			return '' !== $key;
		}
		return 0 === strpos( $key, $rel . '/' );
	}

	/**
	 * Absolute path to the site root without a trailing slash.
	 *
	 * Uses get_home_path(), the supported API for the WordPress install root
	 * (covers installs where WordPress lives in a subdirectory).
	 */
	private function site_root(): string {
		return untrailingslashit( get_home_path() );
	}

	/**
	 * Builds the selectable directory map [slug => absolute path].
	 *
	 * @return array<string, string>
	 */
	private function directory_options(): array {
		$root = $this->site_root();

		$options = array(
			'root'        => $root,
			'wp-admin'    => $root . '/wp-admin',
			'wp-includes' => $root . '/wp-includes',
			'wp-content'  => $root . '/wp-content',
		);

		// E2E test: if a test directory was set via transient, add it.
		$e2e_dir = get_transient( 'integrum_security_scanner_e2e_dir' );
		if ( false !== $e2e_dir && is_string( $e2e_dir ) && '' !== $e2e_dir ) {
			$options['e2e-test'] = $e2e_dir;
		}

		return $options;
	}

	/**
	 * Stores a notice in a transient and redirects back to the page.
	 *
	 * @param array{type: string, message: string} $notice Notice.
	 */
	private function redirect( array $notice ): void {
		set_transient( 'integrum_security_scanner_notice', $notice, 60 );
		wp_safe_redirect( admin_url( 'admin.php?page=' . self::SLUG ) );
		exit;
	}

	/**
	 * Reads and clears the one-shot "scan just started" transient.
	 *
	 * Set by handle_start_scan() right before the PRG redirect and consumed
	 * here on the first render so the UI shows the running scan exactly once.
	 * Any subsequent load (reload, reopening the page) finds it gone and renders
	 * the idle state, preventing the scan from being silently resumed.
	 *
	 * @return string Job id, or '' when no scan was just started.
	 */
	private function consume_started_job(): string {
		$job_id = get_transient( 'integrum_security_scanner_started_job' );
		if ( false !== $job_id ) {
			delete_transient( 'integrum_security_scanner_started_job' );
			return (string) $job_id;
		}
		return '';
	}

	/**
	 * Pops the one-shot transient notice for inline display on the plugin page.
	 *
	 * Rendered inline in the page view (under the relevant section) rather than
	 * via `admin_notices`: that hook fires in admin-header, before the page
	 * callback, and would consume the transient before `render()` can read it.
	 * The `scope` ("connection" or "scan") routes the notice to the section
	 * that triggered it, so e.g. a scan-start error lands near the scan form,
	 * not under the connection form.
	 *
	 * @return array{type: string, message: string, scope: string}|null Notice data or null when none pending.
	 */
	private function consume_notice(): ?array {
		$notice = get_transient( 'integrum_security_scanner_notice' );
		if ( ! is_array( $notice ) ) {
			return null;
		}
		delete_transient( 'integrum_security_scanner_notice' );

		$allowed = array(
			'success' => true,
			'error'   => true,
			'warning' => true,
			'info'    => true,
		);
		$type    = isset( $notice['type'], $allowed[ $notice['type'] ] ) ? $notice['type'] : 'info';
		$message = isset( $notice['message'] ) && is_string( $notice['message'] ) ? $notice['message'] : '';

		if ( '' === $message ) {
			return null;
		}

		$allowed_scopes = array(
			'connection' => true,
			'scan'       => true,
		);
		$scope          = isset( $notice['scope'], $allowed_scopes[ $notice['scope'] ] ) ? $notice['scope'] : 'connection';

		return array(
			'type'    => $type,
			'message' => $message,
			'scope'   => $scope,
		);
	}
}
