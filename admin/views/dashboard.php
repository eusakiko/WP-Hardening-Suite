<?php
/**
 * Dashboard view.
 *
 * @package WP_Sentinel_Security
 * @var array  $score     Security score data from Scoring_Engine::calculate_site_score().
 * @var array  $alerts    Recent alerts.
 * @var object $last_scan Last completed scan object (or null).
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

require SENTINEL_PLUGIN_DIR . 'admin/views/partials/header.php';
?>

<div class="wrap sentinel-wrap">

	<div class="sentinel-page-header">
		<div class="sentinel-header-left">
			<span class="dashicons dashicons-shield-alt sentinel-header-icon"></span>
			<div>
				<h1><?php esc_html_e( 'WP Sentinel Security', 'wp-sentinel-security' ); ?></h1>
				<span class="sentinel-version-badge">v<?php echo esc_html( SENTINEL_VERSION ); ?></span>
			</div>
		</div>
		<div class="sentinel-header-right">
			<a href="<?php echo esc_url( admin_url( 'admin.php?page=sentinel-scanner' ) ); ?>" class="button button-primary sentinel-btn-scan">
				<span class="dashicons dashicons-search"></span>
				<?php esc_html_e( 'Run Scan', 'wp-sentinel-security' ); ?>
			</a>
		</div>
	</div>

	<!-- Executive Summary Panel -->
	<?php
	$risk_level      = Scoring_Engine::get_risk_level( $score['score'] );
	$recommendations = Scoring_Engine::get_top_recommendations( $score, ! empty( $last_scan ) );

	$urgency_labels = array(
		'critical' => __( 'Critical (Do today)', 'wp-sentinel-security' ),
		'high'     => __( 'High (Within 48h)', 'wp-sentinel-security' ),
		'medium'   => __( 'Medium (This week)', 'wp-sentinel-security' ),
		'low'      => __( 'Low (Monitor)', 'wp-sentinel-security' ),
		'info'     => __( 'Info', 'wp-sentinel-security' ),
	);
	?>
	<div class="sentinel-card sentinel-executive-summary">
		<div class="sentinel-executive-top">
			<div class="sentinel-executive-risk">
				<span class="sentinel-executive-risk-label"><?php esc_html_e( 'Overall Risk Level', 'wp-sentinel-security' ); ?></span>
				<span class="sentinel-risk-badge sentinel-risk-<?php echo esc_attr( $risk_level['level'] ); ?>">
					<?php echo esc_html( $risk_level['label'] ); ?>
				</span>
				<p class="sentinel-executive-risk-hint">
					<?php esc_html_e( 'What this means:', 'wp-sentinel-security' ); ?>
					<?php
					$risk_hints = array(
						'critical' => __( 'Your site has active critical vulnerabilities. Immediate action is required.', 'wp-sentinel-security' ),
						'high'     => __( 'Your site has high-severity issues that need urgent attention within 48 hours.', 'wp-sentinel-security' ),
						'medium'   => __( 'Your site has moderate risks that should be addressed this week.', 'wp-sentinel-security' ),
						'low'      => __( 'Your site is mostly secure. Continue monitoring for new issues.', 'wp-sentinel-security' ),
					);
					echo esc_html( $risk_hints[ $risk_level['level'] ] ?? '' );
					?>
				</p>
			</div>
			<div class="sentinel-executive-severity-counts">
				<?php foreach ( $urgency_labels as $sev => $urgency_label ) : ?>
					<?php if ( isset( $score['by_severity'][ $sev ] ) && $score['by_severity'][ $sev ] > 0 ) : ?>
						<div class="sentinel-severity-count-item">
							<span class="sentinel-badge sentinel-badge-<?php echo esc_attr( $sev ); ?>">
								<?php echo esc_html( $urgency_label ); ?>
							</span>
							<strong><?php echo esc_html( $score['by_severity'][ $sev ] ); ?></strong>
						</div>
					<?php endif; ?>
				<?php endforeach; ?>
			</div>
		</div>

		<div class="sentinel-executive-actions">
			<h3><?php esc_html_e( 'Top Recommended Actions', 'wp-sentinel-security' ); ?></h3>
			<ol class="sentinel-recommendations">
				<?php foreach ( $recommendations as $rec ) : ?>
					<li class="sentinel-recommendation-item">
						<span class="sentinel-recommendation-text"><?php echo esc_html( $rec['text'] ); ?></span>
						<a href="<?php echo esc_url( admin_url( 'admin.php?page=' . $rec['page'] ) ); ?>" class="button button-primary button-small sentinel-recommendation-cta">
							<?php echo esc_html( $rec['cta'] ); ?>
						</a>
					</li>
				<?php endforeach; ?>
			</ol>
		</div>
	</div>

	<!-- Score & Stats Row -->
	<div class="sentinel-stats-grid sentinel-grid-4">

		<div class="sentinel-card sentinel-score-card">
			<div class="sentinel-score-circle" style="--score-color: <?php
			// Validate as 6-character hex color; score_to_grade() always returns 6-char colors.
			$color = $score['grade_color'];
			if ( ! preg_match( '/^#[0-9a-fA-F]{6}$/', $color ) ) {
				$color = '#6c757d';
			}
			echo esc_attr( $color );
		?>">
				<span class="sentinel-score-value"><?php echo esc_html( $score['score'] ); ?></span>
				<span class="sentinel-score-grade"><?php echo esc_html( $score['grade'] ); ?></span>
			</div>
			<p class="sentinel-score-label"><?php echo esc_html( $score['grade_label'] ); ?></p>
			<small><?php esc_html_e( 'Security Score', 'wp-sentinel-security' ); ?></small>
		</div>

		<div class="sentinel-card sentinel-stat-card sentinel-stat-critical">
			<div class="sentinel-stat-icon">
				<span class="dashicons dashicons-warning"></span>
			</div>
			<div class="sentinel-stat-content">
				<span class="sentinel-stat-value"><?php echo esc_html( $score['by_severity']['critical'] ); ?></span>
				<span class="sentinel-stat-label"><?php esc_html_e( 'Critical', 'wp-sentinel-security' ); ?></span>
			</div>
		</div>

		<div class="sentinel-card sentinel-stat-card sentinel-stat-high">
			<div class="sentinel-stat-icon">
				<span class="dashicons dashicons-flag"></span>
			</div>
			<div class="sentinel-stat-content">
				<span class="sentinel-stat-value"><?php echo esc_html( $score['by_severity']['high'] ); ?></span>
				<span class="sentinel-stat-label"><?php esc_html_e( 'High', 'wp-sentinel-security' ); ?></span>
			</div>
		</div>

		<div class="sentinel-card sentinel-stat-card sentinel-stat-hardening">
			<div class="sentinel-stat-icon">
				<span class="dashicons dashicons-shield"></span>
			</div>
			<div class="sentinel-stat-content">
				<span class="sentinel-stat-value"><?php echo esc_html( $score['hardening_percentage'] ); ?>%</span>
				<span class="sentinel-stat-label"><?php esc_html_e( 'Hardened', 'wp-sentinel-security' ); ?></span>
			</div>
		</div>

	</div>

	<!-- Charts Row -->
	<div class="sentinel-grid sentinel-grid-2">

		<div class="sentinel-card">
			<h2><?php esc_html_e( 'Security Evolution', 'wp-sentinel-security' ); ?></h2>
			<div class="sentinel-chart-container">
				<canvas id="sentinelScoreChart"></canvas>
			</div>
		</div>

		<div class="sentinel-card">
			<h2><?php esc_html_e( 'Vulnerability Distribution', 'wp-sentinel-security' ); ?></h2>
			<div class="sentinel-chart-container">
				<canvas id="sentinelVulnChart"></canvas>
			</div>
			<div class="sentinel-vuln-legend">
				<?php
				$vuln_colors = array(
					'critical' => '#dc2626',
					'high'     => '#ea580c',
					'medium'   => '#ca8a04',
					'low'      => '#16a34a',
					'info'     => '#2563eb',
				);
				foreach ( $score['by_severity'] as $sev => $count ) :
					?>
					<span class="sentinel-legend-item">
						<span class="sentinel-legend-dot" style="background:<?php echo esc_attr( $vuln_colors[ $sev ] ?? '#6b7280' ); ?>"></span>
						<?php echo esc_html( ucfirst( $sev ) ); ?>: <strong><?php echo esc_html( $count ); ?></strong>
					</span>
				<?php endforeach; ?>
			</div>
		</div>

	</div>

	<!-- Quick Actions Row -->
	<div class="sentinel-grid sentinel-grid-3">

		<div class="sentinel-card sentinel-action-card">
			<span class="dashicons dashicons-search sentinel-action-icon"></span>
			<h3><?php esc_html_e( 'Quick Scan', 'wp-sentinel-security' ); ?></h3>
			<p><?php esc_html_e( 'Run a quick security scan covering core, plugins and configuration.', 'wp-sentinel-security' ); ?></p>
			<button class="button button-primary sentinel-start-scan" data-scan-type="quick">
				<?php esc_html_e( 'Start Quick Scan', 'wp-sentinel-security' ); ?>
			</button>
		</div>

		<div class="sentinel-card sentinel-action-card">
			<span class="dashicons dashicons-backup sentinel-action-icon"></span>
			<h3><?php esc_html_e( 'Create Backup', 'wp-sentinel-security' ); ?></h3>
			<p><?php esc_html_e( 'Create a full database backup before applying security changes.', 'wp-sentinel-security' ); ?></p>
			<button class="button button-secondary sentinel-create-backup">
				<?php esc_html_e( 'Create Backup', 'wp-sentinel-security' ); ?>
			</button>
		</div>

		<div class="sentinel-card sentinel-action-card">
			<span class="dashicons dashicons-media-document sentinel-action-icon"></span>
			<h3><?php esc_html_e( 'Generate Report', 'wp-sentinel-security' ); ?></h3>
			<p><?php esc_html_e( 'Generate a detailed security report with findings and recommendations.', 'wp-sentinel-security' ); ?></p>
			<a href="<?php echo esc_url( admin_url( 'admin.php?page=sentinel-reports' ) ); ?>" class="button button-secondary">
				<?php esc_html_e( 'View Reports', 'wp-sentinel-security' ); ?>
			</a>
		</div>

	</div>

	<!-- Recent Alerts -->
	<div class="sentinel-card">
		<h2><?php esc_html_e( 'Recent Alerts', 'wp-sentinel-security' ); ?></h2>
		<table class="sentinel-table">
			<thead>
				<tr>
					<th><?php esc_html_e( 'Severity', 'wp-sentinel-security' ); ?></th>
					<th><?php esc_html_e( 'Event', 'wp-sentinel-security' ); ?></th>
					<th><?php esc_html_e( 'Description', 'wp-sentinel-security' ); ?></th>
					<th><?php esc_html_e( 'Time', 'wp-sentinel-security' ); ?></th>
				</tr>
			</thead>
			<tbody>
				<?php if ( ! empty( $alerts ) ) : ?>
					<?php foreach ( $alerts as $alert ) : ?>
						<tr>
							<td>
								<span class="sentinel-badge sentinel-badge-<?php echo esc_attr( $alert->severity ); ?>">
									<?php echo esc_html( ucfirst( $alert->severity ) ); ?>
								</span>
							</td>
							<td><?php echo esc_html( $alert->event_type ); ?></td>
							<td><?php echo esc_html( $alert->description ); ?></td>
							<td>
								<?php
								echo esc_html(
									human_time_diff(
										strtotime( $alert->created_at ),
										current_time( 'timestamp' ) // phpcs:ignore WordPress.DateTime.CurrentTimeTimestamp.Requested
									) . ' ' . __( 'ago', 'wp-sentinel-security' )
								);
								?>
							</td>
						</tr>
					<?php endforeach; ?>
				<?php else : ?>
					<tr>
						<td colspan="4"><?php esc_html_e( 'No alerts found. Your site looks clean!', 'wp-sentinel-security' ); ?></td>
					</tr>
				<?php endif; ?>
			</tbody>
		</table>
	</div>

	<!-- Last Scan Info -->
	<div class="sentinel-card sentinel-last-scan">
		<h2><?php esc_html_e( 'Last Scan', 'wp-sentinel-security' ); ?></h2>
		<?php if ( $last_scan ) : ?>
			<div class="sentinel-last-scan-info">
				<div>
					<strong><?php esc_html_e( 'Type:', 'wp-sentinel-security' ); ?></strong>
					<?php echo esc_html( ucfirst( $last_scan->scan_type ) ); ?>
				</div>
				<div>
					<strong><?php esc_html_e( 'Completed:', 'wp-sentinel-security' ); ?></strong>
					<?php echo esc_html( $last_scan->completed_at ); ?>
				</div>
				<div>
					<strong><?php esc_html_e( 'Issues Found:', 'wp-sentinel-security' ); ?></strong>
					<?php echo esc_html( $last_scan->vulnerabilities_found ); ?>
				</div>
				<div>
					<strong><?php esc_html_e( 'Risk Score:', 'wp-sentinel-security' ); ?></strong>
					<?php echo esc_html( $last_scan->risk_score ); ?>
				</div>
			</div>
		<?php else : ?>
			<p><?php esc_html_e( 'No scan has been run yet. Run your first scan to get started.', 'wp-sentinel-security' ); ?></p>
			<a href="<?php echo esc_url( admin_url( 'admin.php?page=sentinel-scanner' ) ); ?>" class="button button-primary">
				<?php esc_html_e( 'Run First Scan', 'wp-sentinel-security' ); ?>
			</a>
		<?php endif; ?>
	</div>

</div>

<script>
jQuery(function($) {
	// Score evolution chart.
	var scoreCtx = document.getElementById('sentinelScoreChart');
	if (scoreCtx && typeof Chart !== 'undefined' && sentinelData.scoreHistory) {
		var labels = sentinelData.scoreHistory.map(function(d) { return d.date; });
		var data   = sentinelData.scoreHistory.map(function(d) { return parseFloat(d.avg_score); });
		new Chart(scoreCtx, {
			type: 'line',
			data: {
				labels: labels.length ? labels : ['<?php echo esc_js( __( 'No data', 'wp-sentinel-security' ) ); ?>'],
				datasets: [{
					label: '<?php echo esc_js( __( 'Security Score', 'wp-sentinel-security' ) ); ?>',
					data: data.length ? data : [0],
					borderColor: '#6366f1',
					backgroundColor: 'rgba(99,102,241,0.1)',
					tension: 0.4,
					fill: true
				}]
			},
			options: {
				responsive: true,
				maintainAspectRatio: false,
				scales: { y: { min: 0, max: 100 } }
			}
		});
	}

	// Vulnerability distribution chart.
	var vulnCtx = document.getElementById('sentinelVulnChart');
	if (vulnCtx && typeof Chart !== 'undefined') {
		new Chart(vulnCtx, {
			type: 'doughnut',
			data: {
				labels: ['<?php echo esc_js( __( 'Critical', 'wp-sentinel-security' ) ); ?>', '<?php echo esc_js( __( 'High', 'wp-sentinel-security' ) ); ?>', '<?php echo esc_js( __( 'Medium', 'wp-sentinel-security' ) ); ?>', '<?php echo esc_js( __( 'Low', 'wp-sentinel-security' ) ); ?>', '<?php echo esc_js( __( 'Info', 'wp-sentinel-security' ) ); ?>'],
				datasets: [{
					data: [
						<?php echo esc_js( $score['by_severity']['critical'] ); ?>,
						<?php echo esc_js( $score['by_severity']['high'] ); ?>,
						<?php echo esc_js( $score['by_severity']['medium'] ); ?>,
						<?php echo esc_js( $score['by_severity']['low'] ); ?>,
						<?php echo esc_js( $score['by_severity']['info'] ); ?>
					],
					backgroundColor: ['#dc2626', '#ea580c', '#ca8a04', '#16a34a', '#2563eb']
				}]
			},
			options: { responsive: true, maintainAspectRatio: false }
		});
	}
});
</script>
