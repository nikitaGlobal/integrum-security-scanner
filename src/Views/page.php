<?php
/**
 * Admin page template.
 *
 * Styling is driven by Tailwind utilities (loaded via the pre-built stylesheet
 * scoped to #integrum-security-scanner-app — see AdminController::enqueue()). The handful
 * of classes kept without Tailwind counterparts (iss-status, iss-progress__*,
 * iss-tree*, iss-node-badge, iss-sev*, iss-file-detail*) are required by
 * assets/js/admin.js, which builds those nodes at runtime and reads/writes them
 * by class name.
 *
 * The scan area is a unified tree: the directory selector carries the
 * files-to-scan preview (pending rows under each selected folder), the live
 * progress bar (while a job runs) and the per-folder results once it
 * finishes.
 *
 * @package Integrum\SecurityScanner\Views
 *
 * @var string|null                                 $site_id
 * @var string|null                                 $site_key
 * @var bool                                        $has_key
 * @var string                                      $job_id
 * @var array{type: string, message: string, scope: string}|null    $notice
 * @var array<string, string>                       $dir_options
 * @var array{directories: string[], include: string, exclude: string, tree: array<string,bool>} $settings
 * @var array<string,bool>                          $tree_flags
 * @var array<int, array{rel: string, name: string, slug: string, has_children: bool, checked: bool}> $tree_rows
 * @var bool                                        $tree_root_on
 * @var array<int, array<string, mixed>>            $history_rows
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
<div class="wrap integrum-security-scanner" id="integrum-security-scanner-app">

	<header class="flex items-center gap-3 mt-1 mb-6">
		<span class="inline-flex h-11 w-11 items-center justify-center rounded-xl bg-primary-600 text-white shadow-sm">
			<span class="dashicons dashicons-shield-alt text-xl" aria-hidden="true"></span>
		</span>
		<div class="min-w-0">
			<h1 class="!m-0 !text-2xl !font-semibold !leading-tight !text-slate-800"><?php esc_html_e( 'Integrum Security Scanner', 'integrum-security-scanner' ); ?></h1>
			<p class="!m-0 !text-sm !text-slate-500"><?php esc_html_e( 'Scan your site files for malicious code.', 'integrum-security-scanner' ); ?></p>
		</div>
		<?php if ( $has_key ) : ?>
			<span class="ml-auto inline-flex items-center gap-1.5 rounded-full bg-emerald-50 px-3 py-1 text-xs font-medium text-emerald-700 ring-1 ring-inset ring-emerald-600/20">
				<span class="h-1.5 w-1.5 rounded-full bg-emerald-500"></span>
				<?php esc_html_e( 'Connected', 'integrum-security-scanner' ); ?>
			</span>
		<?php else : ?>
			<span class="ml-auto inline-flex items-center gap-1.5 rounded-full bg-amber-50 px-3 py-1 text-xs font-medium text-amber-700 ring-1 ring-inset ring-amber-600/20">
				<span class="h-1.5 w-1.5 rounded-full bg-amber-500"></span>
				<?php esc_html_e( 'Not connected', 'integrum-security-scanner' ); ?>
			</span>
		<?php endif; ?>
	</header>

	<div class="grid grid-cols-1 gap-5">

		<!-- Connection / site key -->
		<section class="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
			<div class="mb-4 flex flex-wrap items-center justify-between gap-2">
				<h2 class="!m-0 !text-lg !font-semibold !text-slate-800"><?php esc_html_e( 'Connection', 'integrum-security-scanner' ); ?></h2>
				<?php if ( $has_key && null !== $site_id ) : ?>
					<span class="text-xs text-slate-500">
						<?php
						printf(
							/* translators: %s: site id. */
							esc_html__( 'Site ID: %s', 'integrum-security-scanner' ),
							'<code class="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[11px] text-slate-700">' . esc_html( $site_id ) . '</code>'
						);
						?>
					</span>
				<?php endif; ?>
			</div>

			<form method="post" action="" class="grid grid-cols-1 gap-4 md:grid-cols-2">
				<?php wp_nonce_field( 'integrum_security_scanner_get_key' ); ?>
				<input type="hidden" name="integrum_security_scanner_action" value="get_key" />

				<div>
					<label for="iss-email" class="mb-1.5 block text-sm font-medium text-slate-700"><?php esc_html_e( 'Owner email', 'integrum-security-scanner' ); ?></label>
					<input
						type="email"
						id="iss-email"
						name="integrum_security_scanner_email"
						required
						value="<?php echo esc_attr( wp_get_current_user()->user_email ); ?>"
						class="block w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800 shadow-sm outline-none transition focus:border-primary-500 focus:ring-2 focus:ring-primary-500/30"
					/>
				</div>

				<div>
					<label for="iss-key" class="mb-1.5 block text-sm font-medium text-slate-700"><?php esc_html_e( 'Site key', 'integrum-security-scanner' ); ?></label>
					<div class="relative">
						<input
							type="password"
							id="iss-key"
							name="integrum_security_scanner_key"
							value="<?php echo esc_attr( $site_key ?? '' ); ?>"
							autocomplete="off"
							class="block w-full rounded-md border border-slate-300 bg-white px-3 py-2 pr-10 font-mono text-sm text-slate-800 shadow-sm outline-none transition focus:border-primary-500 focus:ring-2 focus:ring-primary-500/30"
						/>
						<button
							type="button"
							id="iss-key-toggle"
							aria-pressed="false"
							aria-label="<?php esc_attr_e( 'Show site key', 'integrum-security-scanner' ); ?>"
							class="absolute inset-y-0 right-0 flex cursor-pointer items-center pr-3 text-slate-500 transition hover:text-slate-700"
						>
							<svg class="iss-key-icon h-5 w-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" aria-hidden="true">
								<path stroke-linecap="round" stroke-linejoin="round" d="M2.036 12.322a1.012 1.012 0 010-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178z" />
								<path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
							</svg>
							<svg class="iss-key-icon iss-key-icon--off h-5 w-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" aria-hidden="true" hidden>
								<path stroke-linecap="round" stroke-linejoin="round" d="M3.98 8.223A10.477 10.477 0 001.934 12C3.226 16.338 7.244 19.5 12 19.5c.993 0 1.953-.138 2.863-.395M6.228 6.228A10.45 10.45 0 0112 4.5c4.756 0 8.773 3.162 10.065 7.498a10.523 10.523 0 01-4.293 5.774M6.228 6.228L3 3m3.228 3.228l3.65 3.65m7.894 7.894L21 21m-3.228-3.228l-3.65-3.65m0 0a3 3 0 10-4.243-4.243m4.242 4.242L9.88 9.88" />
							</svg>
						</button>
					</div>
				</div>

				<div id="iss-terms-row" class="md:col-span-2" <?php echo $has_key ? 'hidden' : ''; ?>>
					<label class="flex cursor-pointer items-start gap-2.5">
						<input
							type="checkbox"
							id="iss-terms-agree"
							name="integrum_security_scanner_terms"
							value="1"
							class="mt-0.5 rounded border-slate-300 text-primary-600 focus:ring-primary-500"
							<?php echo $has_key ? '' : 'required'; ?>
						/>
						<span class="text-sm leading-relaxed text-slate-600">
							<?php esc_html_e( 'I agree to the', 'integrum-security-scanner' ); ?>
							<button
								type="button"
								class="iss-terms-open cursor-pointer border-0 bg-transparent p-0 text-inherit underline decoration-dotted underline-offset-2 hover:text-slate-800"
							><?php esc_html_e( 'Limit Login Attempts Reloaded Terms of Service and Malware Scanning Terms', 'integrum-security-scanner' ); ?></button>
							<?php
							printf(
								wp_kses(
									/* translators: 1: Privacy Policy label, 2: Imunify partner. */
									__( ', and acknowledge the %1$s. Malware scanning is provided by Limit Login Attempts Reloaded in partnership with %2$s', 'integrum-security-scanner' ),
									array( 'strong' => array() )
								),
								'<strong>' . esc_html__( 'Privacy Policy', 'integrum-security-scanner' ) . '</strong>',
								'<strong>' . esc_html__( 'Imunify by CloudLinux.', 'integrum-security-scanner' ) . '</strong>'
							);
							?>
						</span>
					</label>
				</div>

				<div class="md:col-span-2">
					<button
						type="submit"
						id="iss-key-submit"
						class="inline-flex items-center gap-2 rounded-md bg-primary-600 px-4 py-2 text-sm font-medium text-white shadow-sm transition hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-primary-500/40 disabled:cursor-not-allowed disabled:opacity-60"
						<?php disabled( ! $has_key ); ?>
					>
						<?php $has_key ? esc_html_e( 'Save key', 'integrum-security-scanner' ) : esc_html_e( 'Register', 'integrum-security-scanner' ); ?>
					</button>
				</div>

				<?php if ( null !== $notice && 'connection' === $notice['scope'] ) : ?>
					<?php require INTEGRUM_SECURITY_SCANNER_DIR . 'src/Views/notice.php'; ?>
				<?php endif; ?>
			</form>

			<?php require INTEGRUM_SECURITY_SCANNER_DIR . 'src/Views/terms-modal.php'; ?>
		</section>

		<!-- Scan area: directory selection + live progress + results (unified tree) -->
		<section class="rounded-xl border border-slate-200 bg-white p-6 shadow-sm <?php echo $has_key ? '' : 'pointer-events-none opacity-60'; ?>">
			<h2 class="!m-0 !mb-4 !text-lg !font-semibold !text-slate-800"><?php esc_html_e( 'Scan area', 'integrum-security-scanner' ); ?></h2>

			<!-- Scan status (revealed by admin.js once a job is active) -->
			<div class="iss-status mb-4 rounded-lg bg-slate-50 p-4" hidden>
				<div class="mb-2 flex items-center justify-between">
					<span class="inline-flex items-center gap-1.5 rounded-full bg-primary-50 px-2.5 py-1 text-xs font-medium text-primary-700">
						<span class="h-1.5 w-1.5 animate-pulse rounded-full bg-primary-500"></span>
						<?php esc_html_e( 'Live', 'integrum-security-scanner' ); ?>
					</span>
					<span class="text-xs text-slate-500"><?php esc_html_e( 'Do not close this page until the scan completes.', 'integrum-security-scanner' ); ?></span>
				</div>
				<div class="iss-progress h-2.5 w-full overflow-hidden rounded-full bg-slate-100">
					<div class="iss-progress__bar h-full rounded-full bg-gradient-to-r from-primary-500 to-primary-600 transition-[width] duration-500 ease-out" style="width:0%"></div>
				</div>
				<p class="iss-progress__label mt-2 break-all font-mono text-xs text-slate-600"><?php esc_html_e( 'Preparing…', 'integrum-security-scanner' ); ?></p>
				<input type="hidden" class="iss-job-id" value="<?php echo esc_attr( $job_id ); ?>" />
			</div>

			<!-- Scan completion summary (revealed and filled by admin.js when the job finishes) -->
			<div class="iss-scan-summary mb-4 rounded-lg border px-4 py-3 text-sm" role="status" hidden></div>

			<form method="post" action="" class="iss-start-form space-y-4">
				<?php wp_nonce_field( 'integrum_security_scanner_start_scan' ); ?>
				<input type="hidden" name="integrum_security_scanner_action" value="start_scan" />

				<div>
					<div class="mb-2 flex flex-wrap items-center justify-between gap-2">
						<span class="inline-flex items-baseline gap-2">
							<span class="text-sm font-medium text-slate-700"><?php esc_html_e( 'Directories', 'integrum-security-scanner' ); ?></span>
							<!-- Files-in-scope counter, filled by admin.js from the preview -->
							<span class="iss-preview__count font-mono text-xs text-slate-500"></span>
						</span>
						<!-- Revealed by admin.js once results are attached to the tree -->
						<label id="iss-only-suspicious-wrap" class="inline-flex cursor-pointer items-center gap-2 text-sm text-slate-600" hidden>
							<input type="checkbox" id="iss-only-suspicious" checked class="rounded border-slate-300 text-primary-600 focus:ring-primary-500" />
							<?php esc_html_e( 'Suspicious only', 'integrum-security-scanner' ); ?>
						</label>
					</div>
					<p class="!m-0 !mb-2 text-xs text-slate-500"><?php esc_html_e( 'Checking a folder selects all its subfolders; unchecking a subfolder clears its parent.', 'integrum-security-scanner' ); ?></p>
					<div
						class="iss-tree iss-dirtree rounded-md border border-slate-200 bg-slate-50"
						data-flags="<?php echo esc_attr( wp_json_encode( $tree_flags ) ); ?>"
					>
						<ul class="iss-tree__list is-root">
							<li class="iss-tree__folder iss-dirtree__node" data-rel="">
								<span class="iss-tree__toggle">▾</span>
								<label class="iss-dirtree__label inline-flex cursor-pointer items-center gap-2">
									<input
										type="checkbox"
										name="integrum_security_scanner_directories[]"
										value="root"
										class="rounded border-slate-300 text-primary-600 focus:ring-primary-500"
										<?php checked( $tree_root_on ); ?>
									/>
									<span class="iss-tree__folder-name">/</span>
								</label>
								<ul class="iss-tree__list" data-loaded="1">
									<?php foreach ( $tree_rows as $row ) : ?>
										<li class="iss-tree__folder iss-dirtree__node" data-rel="<?php echo esc_attr( $row['rel'] ); ?>">
											<span class="iss-tree__toggle"><?php echo $row['has_children'] ? '▸' : ' '; ?></span>
											<label class="iss-dirtree__label inline-flex cursor-pointer items-center gap-2">
												<?php if ( '' !== $row['slug'] ) : ?>
													<input
															type="checkbox"
														name="integrum_security_scanner_directories[]"
														value="<?php echo esc_attr( $row['slug'] ); ?>"
														class="rounded border-slate-300 text-primary-600 focus:ring-primary-500"
														<?php checked( $row['checked'] ); ?>
													/>
												<?php else : ?>
													<input
														type="checkbox"
														class="rounded border-slate-300 text-primary-600 focus:ring-primary-500"
														<?php checked( $row['checked'] ); ?>
													/>
												<?php endif; ?>
												<span class="iss-tree__folder-name"><?php echo esc_html( $row['name'] ); ?>/</span>
											</label>
											<ul class="iss-tree__list" hidden></ul>
										</li>
									<?php endforeach; ?>
								</ul>
								</li>
							</ul>
							<div class="iss-tree-flags" hidden></div>
						</div>
						<p class="iss-preview__loading !m-0 !mt-2 text-xs text-slate-500"><?php esc_html_e( 'Loading…', 'integrum-security-scanner' ); ?></p>
						<p class="iss-preview__empty !m-0 !mt-2 text-xs text-slate-500" hidden><?php esc_html_e( 'No files match the current settings.', 'integrum-security-scanner' ); ?></p>
					</div>

				<div class="grid grid-cols-1 gap-4 md:grid-cols-2">
					<div>
						<label for="iss-include" class="mb-1.5 block text-sm font-medium text-slate-700"><?php esc_html_e( 'Include masks', 'integrum-security-scanner' ); ?></label>
						<input
							type="text"
							id="iss-include"
							name="integrum_security_scanner_include"
							placeholder="Example: *.php"
							value="<?php echo esc_attr( $settings['include'] ); ?>"
							class="block w-full rounded-md border border-slate-300 bg-white px-3 py-2 font-mono text-sm text-slate-800 shadow-sm outline-none transition focus:border-primary-500 focus:ring-2 focus:ring-primary-500/30"
						/>
					</div>
					<div>
						<label for="iss-exclude" class="mb-1.5 block text-sm font-medium text-slate-700"><?php esc_html_e( 'Exclude masks', 'integrum-security-scanner' ); ?></label>
						<input
							type="text"
							id="iss-exclude"
							name="integrum_security_scanner_exclude"
							placeholder="Example: */cache/*"
							value="<?php echo esc_attr( $settings['exclude'] ); ?>"
							class="block w-full rounded-md border border-slate-300 bg-white px-3 py-2 font-mono text-sm text-slate-800 shadow-sm outline-none transition focus:border-primary-500 focus:ring-2 focus:ring-primary-500/30"
						/>
					</div>
				</div>

				<p class="!m-0 text-xs text-slate-500"><?php esc_html_e( 'Separate masks with a comma. Exclude always wins over include.', 'integrum-security-scanner' ); ?></p>

				<div class="iss-scan-actions flex items-center gap-3 pt-1">
					<button
						type="submit"
						class="iss-scan-actions__start inline-flex items-center gap-2 rounded-md bg-primary-600 px-4 py-2 text-sm font-medium text-white shadow-sm transition hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-primary-500/40 disabled:cursor-not-allowed disabled:opacity-60"
						<?php disabled( ! $has_key || '' !== $job_id ); ?>
					>
						<?php esc_html_e( 'Start Scan', 'integrum-security-scanner' ); ?>
					</button>
					<button
						type="button"
						class="iss-scan-actions__stop inline-flex items-center gap-2 rounded-md border border-slate-300 bg-white px-4 py-2 text-sm font-medium text-slate-700 shadow-sm transition hover:bg-slate-50 focus:outline-none focus:ring-2 focus:ring-slate-400/30 disabled:cursor-not-allowed disabled:opacity-60"
						<?php disabled( '' === $job_id ); ?>
					>
						<?php esc_html_e( 'Stop Scan', 'integrum-security-scanner' ); ?>
					</button>
				</div>
			</form>

			<?php if ( null !== $notice && 'scan' === $notice['scope'] ) : ?>
				<?php require INTEGRUM_SECURITY_SCANNER_DIR . 'src/Views/notice.php'; ?>
			<?php endif; ?>
		</section>

		<section class="iss-history rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
			<h2 class="!m-0 !mb-1 !text-lg !font-semibold !text-slate-800"><?php esc_html_e( 'Scan history', 'integrum-security-scanner' ); ?></h2>
			<p class="!m-0 !mb-4 text-xs text-slate-500"><?php esc_html_e( 'Past scans, newest first. Click a row to see the files with problems.', 'integrum-security-scanner' ); ?></p>
			<div class="overflow-x-auto">
				<table class="iss-history__table w-full text-left text-sm">
					<thead>
						<tr>
							<th class="iss-history__th"><?php esc_html_e( 'Date', 'integrum-security-scanner' ); ?></th>
							<th class="iss-history__th"><?php esc_html_e( 'Problems found', 'integrum-security-scanner' ); ?></th>
							<th class="iss-history__th"><?php esc_html_e( 'Files scanned', 'integrum-security-scanner' ); ?></th>
						</tr>
					</thead>
					<tbody class="iss-history__body">
						<?php foreach ( $history_rows as $run ) : ?>
							<tr class="iss-history__row" data-job="<?php echo esc_attr( $run['job_id'] ); ?>" aria-expanded="false">
								<td class="iss-history__td"><?php echo esc_html( $run['date'] ); ?></td>
								<td class="iss-history__td"><span class="iss-history__count<?php echo $run['problems'] > 0 ? ' iss-history__count--alert' : ' iss-history__count--ok'; ?>"><?php echo esc_html( (string) $run['problems'] ); ?></span></td>
								<td class="iss-history__td iss-history__td--muted"><?php echo esc_html( (string) $run['scanned'] ); ?></td>
							</tr>
							<tr class="iss-history__detail" hidden>
								<td colspan="3" class="iss-history__detail-td">
									<div class="iss-tree iss-history__tree" data-job="<?php echo esc_attr( $run['job_id'] ); ?>"></div>
								</td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			</div>
			<p class="iss-history__empty !m-0 text-sm text-slate-500" <?php echo array() === $history_rows ? '' : 'hidden'; ?>><?php esc_html_e( 'No scans yet.', 'integrum-security-scanner' ); ?></p>
		</section>

</div>
</div>
