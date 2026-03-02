<?php
/**
 * Scanner view.
 *
 * @package WP_Sentinel_Security
 * @var array $scan_history Recent scan history.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

require SENTINEL_PLUGIN_DIR . 'admin/views/partials/header.php';
?>

<div class="wrap sentinel-wrap">

	<div class="sentinel-page-header">
		<div class="sentinel-header-left">
			<span class="dashicons dashicons-search sentinel-header-icon"></span>
			<h1><?php esc_html_e( 'Security Scanner', 'wp-sentinel-security' ); ?></h1>
		</div>
	</div>

	<!-- Scan Type Cards -->
	<h2><?php esc_html_e( 'Select Scan Type', 'wp-sentinel-security' ); ?></h2>
	<div class="sentinel-grid sentinel-scan-types">

		<div class="sentinel-card sentinel-scan-type-card">
			<span class="dashicons dashicons-search sentinel-scan-icon"></span>
			<h3><?php esc_html_e( 'Full Scan', 'wp-sentinel-security' ); ?></h3>
			<p><?php esc_html_e( 'Comprehensive scan of all components (5–10 min).', 'wp-sentinel-security' ); ?></p>
			<button class="button button-primary sentinel-start-scan" data-scan-type="full">
				<?php esc_html_e( 'Start Full Scan', 'wp-sentinel-security' ); ?>
			</button>
		</div>

		<div class="sentinel-card sentinel-scan-type-card">
			<span class="dashicons dashicons-performance sentinel-scan-icon"></span>
			<h3><?php esc_html_e( 'Quick Scan', 'wp-sentinel-security' ); ?></h3>
			<p><?php esc_html_e( 'Fast scan: core, plugins, and config (1–2 min).', 'wp-sentinel-security' ); ?></p>
			<button class="button button-primary sentinel-start-scan" data-scan-type="quick">
				<?php esc_html_e( 'Start Quick Scan', 'wp-sentinel-security' ); ?>
			</button>
		</div>

		<div class="sentinel-card sentinel-scan-type-card">
			<span class="dashicons dashicons-wordpress sentinel-scan-icon"></span>
			<h3><?php esc_html_e( 'Core Integrity', 'wp-sentinel-security' ); ?></h3>
			<p><?php esc_html_e( 'Verify WordPress core file integrity (1 min).', 'wp-sentinel-security' ); ?></p>
			<button class="button button-secondary sentinel-start-scan" data-scan-type="core">
				<?php esc_html_e( 'Scan Core', 'wp-sentinel-security' ); ?>
			</button>
		</div>

		<div class="sentinel-card sentinel-scan-type-card">
			<span class="dashicons dashicons-plugins-checked sentinel-scan-icon"></span>
			<h3><?php esc_html_e( 'Plugins', 'wp-sentinel-security' ); ?></h3>
			<p><?php esc_html_e( 'Check installed plugins for vulnerabilities (2–3 min).', 'wp-sentinel-security' ); ?></p>
			<button class="button button-secondary sentinel-start-scan" data-scan-type="plugins">
				<?php esc_html_e( 'Scan Plugins', 'wp-sentinel-security' ); ?>
			</button>
		</div>

		<div class="sentinel-card sentinel-scan-type-card">
			<span class="dashicons dashicons-art sentinel-scan-icon"></span>
			<h3><?php esc_html_e( 'Themes', 'wp-sentinel-security' ); ?></h3>
			<p><?php esc_html_e( 'Check installed themes for vulnerabilities (1–2 min).', 'wp-sentinel-security' ); ?></p>
			<button class="button button-secondary sentinel-start-scan" data-scan-type="themes">
				<?php esc_html_e( 'Scan Themes', 'wp-sentinel-security' ); ?>
			</button>
		</div>

		<div class="sentinel-card sentinel-scan-type-card">
			<span class="dashicons dashicons-media-document sentinel-scan-icon"></span>
			<h3><?php esc_html_e( 'File Monitor', 'wp-sentinel-security' ); ?></h3>
			<p><?php esc_html_e( 'Detect unauthorized file changes and malware (3–5 min).', 'wp-sentinel-security' ); ?></p>
			<button class="button button-secondary sentinel-start-scan" data-scan-type="files">
				<?php esc_html_e( 'Scan Files', 'wp-sentinel-security' ); ?>
			</button>
		</div>

		<div class="sentinel-card sentinel-scan-type-card">
			<span class="dashicons dashicons-admin-settings sentinel-scan-icon"></span>
			<h3><?php esc_html_e( 'Configuration', 'wp-sentinel-security' ); ?></h3>
			<p><?php esc_html_e( 'Analyze WordPress and PHP configuration (~30 s).', 'wp-sentinel-security' ); ?></p>
			<button class="button button-secondary sentinel-start-scan" data-scan-type="config">
				<?php esc_html_e( 'Scan Config', 'wp-sentinel-security' ); ?>
			</button>
		</div>

	</div>

	<!-- Scan Progress (hidden by default) -->
	<div id="sentinel-scan-progress" class="sentinel-card" style="display:none;">
		<h2><?php esc_html_e( 'Scan in Progress', 'wp-sentinel-security' ); ?></h2>
		<div class="sentinel-progress-bar-wrap">
			<div class="sentinel-progress-bar">
				<div class="sentinel-progress-fill" id="sentinelProgressFill" style="width:0%"></div>
			</div>
			<span id="sentinelProgressText">0%</span>
		</div>
		<p id="sentinelProgressStatus"><?php esc_html_e( 'Initializing scan...', 'wp-sentinel-security' ); ?></p>
		<button class="button button-secondary" id="sentinelCancelScan">
			<?php esc_html_e( 'Cancel Scan', 'wp-sentinel-security' ); ?>
		</button>
	</div>

	<!-- Results Section (hidden by default) -->
	<div id="sentinel-scan-results" class="sentinel-card" style="display:none;">
		<h2><?php esc_html_e( 'Scan Results', 'wp-sentinel-security' ); ?></h2>

		<!-- Severity filter tabs -->
		<div class="sentinel-filter-tabs">
			<button class="sentinel-tab active" data-filter="all"><?php esc_html_e( 'All', 'wp-sentinel-security' ); ?></button>
			<button class="sentinel-tab sentinel-tab-critical" data-filter="critical"><?php esc_html_e( 'Critical (Do today)', 'wp-sentinel-security' ); ?></button>
			<button class="sentinel-tab sentinel-tab-high" data-filter="high"><?php esc_html_e( 'High (Within 48h)', 'wp-sentinel-security' ); ?></button>
			<button class="sentinel-tab sentinel-tab-medium" data-filter="medium"><?php esc_html_e( 'Medium (This week)', 'wp-sentinel-security' ); ?></button>
			<button class="sentinel-tab sentinel-tab-low" data-filter="low"><?php esc_html_e( 'Low (Monitor)', 'wp-sentinel-security' ); ?></button>
			<button class="sentinel-tab sentinel-tab-info" data-filter="info"><?php esc_html_e( 'Info', 'wp-sentinel-security' ); ?></button>
		</div>

		<table class="sentinel-table" id="sentinelResultsTable">
			<thead>
				<tr>
					<th><?php esc_html_e( 'Severity', 'wp-sentinel-security' ); ?></th>
					<th><?php esc_html_e( 'Component', 'wp-sentinel-security' ); ?></th>
					<th><?php esc_html_e( 'Title', 'wp-sentinel-security' ); ?></th>
					<th><?php esc_html_e( 'CVSS', 'wp-sentinel-security' ); ?></th>
					<th><?php esc_html_e( 'Actions', 'wp-sentinel-security' ); ?></th>
				</tr>
			</thead>
			<tbody id="sentinelResultsBody">
				<tr>
					<td colspan="5"><?php esc_html_e( 'No results yet.', 'wp-sentinel-security' ); ?></td>
				</tr>
			</tbody>
		</table>
	</div>

	<!-- Scan History -->
	<div class="sentinel-card">
		<h2><?php esc_html_e( 'Scan History', 'wp-sentinel-security' ); ?></h2>
		<table class="sentinel-table">
			<thead>
				<tr>
					<th><?php esc_html_e( 'Type', 'wp-sentinel-security' ); ?></th>
					<th><?php esc_html_e( 'Status', 'wp-sentinel-security' ); ?></th>
					<th><?php esc_html_e( 'Started', 'wp-sentinel-security' ); ?></th>
					<th><?php esc_html_e( 'Duration', 'wp-sentinel-security' ); ?></th>
					<th><?php esc_html_e( 'Issues', 'wp-sentinel-security' ); ?></th>
					<th><?php esc_html_e( 'Score', 'wp-sentinel-security' ); ?></th>
				</tr>
			</thead>
			<tbody>
				<?php if ( ! empty( $scan_history ) ) : ?>
					<?php foreach ( $scan_history as $scan ) : ?>
						<?php
						$duration = '';
						if ( $scan->completed_at && $scan->started_at ) {
							$secs     = strtotime( $scan->completed_at ) - strtotime( $scan->started_at );
							$duration = $secs >= 60
								? floor( $secs / 60 ) . 'm ' . ( $secs % 60 ) . 's'
								: $secs . 's';
						}
						?>
						<tr>
							<td><?php echo esc_html( ucfirst( $scan->scan_type ) ); ?></td>
							<td>
								<span class="sentinel-badge sentinel-badge-<?php echo esc_attr( $scan->status ); ?>">
									<?php echo esc_html( ucfirst( $scan->status ) ); ?>
								</span>
							</td>
							<td><?php echo esc_html( $scan->started_at ); ?></td>
							<td><?php echo esc_html( $duration ); ?></td>
							<td><?php echo esc_html( $scan->vulnerabilities_found ); ?></td>
							<td><?php echo esc_html( $scan->risk_score ); ?></td>
						</tr>
					<?php endforeach; ?>
				<?php else : ?>
					<tr>
						<td colspan="6"><?php esc_html_e( 'No scans have been run yet.', 'wp-sentinel-security' ); ?></td>
					</tr>
				<?php endif; ?>
			</tbody>
		</table>
	</div>

</div>
