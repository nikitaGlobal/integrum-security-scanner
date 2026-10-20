<?php
/**
 * Terms of Service modal for site registration.
 *
 * @package Integrum\SecurityScanner\Views
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
<dialog
	id="iss-terms-dialog"
	class="iss-terms-dialog w-full max-w-lg rounded-xl border border-slate-200 bg-white p-0 shadow-xl backdrop:bg-slate-900/50"
	aria-labelledby="iss-terms-dialog-title"
>
	<div class="flex items-start justify-between gap-4 border-b border-slate-200 px-6 py-4">
		<h3 id="iss-terms-dialog-title" class="!m-0 !text-base !font-semibold !leading-snug !text-slate-800">
			<?php esc_html_e( 'Integrum Terms of Service and Malware Scanning Terms', 'integrum-security-scanner' ); ?>
		</h3>
		<button
			type="button"
			class="iss-terms-close -mr-1 flex h-8 w-8 shrink-0 cursor-pointer items-center justify-center rounded-md text-slate-500 transition hover:bg-slate-100 hover:text-slate-700"
			aria-label="<?php esc_attr_e( 'Close', 'integrum-security-scanner' ); ?>"
		>
			<span aria-hidden="true">&times;</span>
		</button>
	</div>

	<div class="space-y-3 px-6 py-4 text-sm leading-relaxed text-slate-600">
		<p>
		<?php
		printf(
			wp_kses(
				/* translators: 1: Integrum provider, 2: Imunify partner. */
				__( 'The malware scanning service is provided by %1$s in partnership with %2$s', 'integrum-security-scanner' ),
				array( 'strong' => array() )
			),
			'<strong>' . esc_html__( 'Limit Login Attempts Reloaded', 'integrum-security-scanner' ) . '</strong>',
			'<strong>' . esc_html__( 'Imunify by CloudLinux.', 'integrum-security-scanner' ) . '</strong>'
		);
		?>
		</p>
		<p>
		<?php
		printf(
			wp_kses(
				/* translators: %s: CloudLinux processor. */
				__( 'To detect malware and other security threats in your WordPress installation, information about scanned files — including file metadata, file hashes, and, when required for analysis, file contents — may be securely transmitted to and processed by %s', 'integrum-security-scanner' ),
				array( 'strong' => array() )
			),
			'<strong>' . esc_html__( 'Cloud Linux Software, Inc. using Imunify Connect.', 'integrum-security-scanner' ) . '</strong>'
		);
		?>
		</p>
		<p><?php esc_html_e( 'Your website domain and registration email address will also be transmitted for account registration, service operation, and service-related notifications. This information will not be shared with other third parties for marketing or unrelated purposes.', 'integrum-security-scanner' ); ?></p>
		<p><?php esc_html_e( 'Because website files may contain personal, confidential, or other protected information, by enabling and using malware scanning you confirm that you are authorized to submit these files for security analysis.', 'integrum-security-scanner' ); ?></p>
		<p>
		<?php
		printf(
			wp_kses(
				/* translators: %s: Privacy Policy label. */
				__( 'The processing of data by CloudLinux is subject to its %s and applicable terms.', 'integrum-security-scanner' ),
				array( 'strong' => array() )
			),
			'<strong>' . esc_html__( 'Privacy Policy', 'integrum-security-scanner' ) . '</strong>'
		);
		?>
		</p>
	</div>

	<div class="border-t border-slate-200 px-6 py-4 text-sm leading-relaxed text-slate-600">
		<p class="!m-0">
			<a href="https://www.limitloginattempts.com/terms/" target="_blank" rel="noopener noreferrer" class="underline decoration-dotted underline-offset-2 hover:text-slate-800"><?php esc_html_e( 'Integrum Terms of Service', 'integrum-security-scanner' ); ?></a>
			<?php esc_html_e( ' and ', 'integrum-security-scanner' ); ?>
			<a href="https://www.limitloginattempts.com/privacy-policy/" target="_blank" rel="noopener noreferrer" class="underline decoration-dotted underline-offset-2 hover:text-slate-800"><?php esc_html_e( 'Privacy Policy', 'integrum-security-scanner' ); ?></a>
			<span aria-hidden="true"> · </span>
			<a href="https://cloudlinux.com/clients-privacy-policy/" target="_blank" rel="noopener noreferrer" class="underline decoration-dotted underline-offset-2 hover:text-slate-800"><?php esc_html_e( 'CloudLinux Privacy Policy', 'integrum-security-scanner' ); ?></a>
			<span aria-hidden="true"> · </span>
			<a href="https://imunify360.com/legal/terms-of-use/" target="_blank" rel="noopener noreferrer" class="underline decoration-dotted underline-offset-2 hover:text-slate-800"><?php esc_html_e( 'Imunify Terms of Use', 'integrum-security-scanner' ); ?></a>
			<?php esc_html_e( ' and ', 'integrum-security-scanner' ); ?>
			<a href="https://imunify360.com/legal/" target="_blank" rel="noopener noreferrer" class="underline decoration-dotted underline-offset-2 hover:text-slate-800"><?php esc_html_e( 'Legal Documentation', 'integrum-security-scanner' ); ?></a>
		</p>
	</div>
</dialog>
