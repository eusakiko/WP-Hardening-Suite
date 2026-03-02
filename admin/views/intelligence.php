<?php
/**
 * Intelligence view.
 *
 * Displays environment fingerprint, attack surface map, and risk context analysis.
 *
 * @package WP_Sentinel_Security
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

require SENTINEL_PLUGIN_DIR . 'admin/views/partials/header.php';

// Fetch cached intelligence data (if available).
$intelligence = get_transient( 'sentinel_intelligence_data' );
$env          = is_array( $intelligence ) ? ( $intelligence['environment'] ?? array() ) : array();
$surface      = is_array( $intelligence ) ? ( $intelligence['attack_surface'] ?? array() ) : array();
$timestamp    = is_array( $intelligence ) ? ( $intelligence['timestamp'] ?? '' ) : '';

$sec_headers = $env['security_headers'] ?? array();

$header_labels = array(
	'Strict-Transport-Security' => __( 'HSTS', 'wp-sentinel-security' ),
	'Content-Security-Policy'   => __( 'CSP', 'wp-sentinel-security' ),
	'X-Frame-Options'           => __( 'X-Frame-Options', 'wp-sentinel-security' ),
	'X-Content-Type-Options'    => __( 'X-Content-Type-Options', 'wp-sentinel-security' ),
	'Referrer-Policy'           => __( 'Referrer-Policy', 'wp-sentinel-security' ),
	'Permissions-Policy'        => __( 'Permissions-Policy', 'wp-sentinel-security' ),
	'X-XSS-Protection'          => __( 'X-XSS-Protection', 'wp-sentinel-security' ),
);
?>

<div class="wrap sentinel-wrap">

	<div class="sentinel-page-header">
		<div class="sentinel-header-left">
			<span class="dashicons dashicons-chart-line sentinel-header-icon"></span>
			<div>
				<h1><?php esc_html_e( 'Intelligence Layer', 'wp-sentinel-security' ); ?></h1>
				<?php if ( $timestamp ) : ?>
					<span class="sentinel-version-badge">
						<?php
						echo esc_html(
							sprintf(
								/* translators: %s: datetime string */
								__( 'Last analysis: %s', 'wp-sentinel-security' ),
								$timestamp
							)
						);
						?>
					</span>
				<?php endif; ?>
			</div>
		</div>
		<div class="sentinel-header-right">
			<button id="sentinel-run-intelligence" class="button button-primary">
				<span class="dashicons dashicons-update"></span>
				<?php esc_html_e( 'Run Fresh Analysis', 'wp-sentinel-security' ); ?>
			</button>
		</div>
	</div>

	<div id="sentinel-intelligence-notice" style="display:none;"></div>

	<!-- Environment Fingerprint -->
	<h2><?php esc_html_e( 'Environment Fingerprint', 'wp-sentinel-security' ); ?></h2>
	<div class="sentinel-grid sentinel-grid-3">

		<!-- Server -->
		<div class="sentinel-card">
			<h3><span class="dashicons dashicons-admin-network"></span> <?php esc_html_e( 'Server', 'wp-sentinel-security' ); ?></h3>
			<?php if ( ! empty( $env['server'] ) ) : ?>
				<table class="sentinel-info-table">
					<tr><th><?php esc_html_e( 'Software', 'wp-sentinel-security' ); ?></th><td><?php echo esc_html( $env['server']['software'] ?? '–' ); ?></td></tr>
					<tr><th><?php esc_html_e( 'Type', 'wp-sentinel-security' ); ?></th><td><?php echo esc_html( ucfirst( $env['server']['type'] ?? '–' ) ); ?></td></tr>
					<tr><th><?php esc_html_e( 'OS', 'wp-sentinel-security' ); ?></th><td><?php echo esc_html( $env['server']['os'] ?? '–' ); ?></td></tr>
				</table>
			<?php else : ?>
				<p><?php esc_html_e( 'No data. Run an analysis first.', 'wp-sentinel-security' ); ?></p>
			<?php endif; ?>
		</div>

		<!-- PHP -->
		<div class="sentinel-card">
			<h3><span class="dashicons dashicons-editor-code"></span> <?php esc_html_e( 'PHP', 'wp-sentinel-security' ); ?></h3>
			<?php if ( ! empty( $env['php'] ) ) : ?>
				<table class="sentinel-info-table">
					<tr>
						<th><?php esc_html_e( 'Version', 'wp-sentinel-security' ); ?></th>
						<td>
							<?php echo esc_html( $env['php']['version'] ?? '–' ); ?>
							<?php if ( ! empty( $env['php']['is_eol'] ) ) : ?>
								<span class="sentinel-badge sentinel-badge-critical"><?php esc_html_e( 'EOL', 'wp-sentinel-security' ); ?></span>
							<?php endif; ?>
						</td>
					</tr>
					<tr><th><?php esc_html_e( 'SAPI', 'wp-sentinel-security' ); ?></th><td><?php echo esc_html( $env['php']['sapi'] ?? '–' ); ?></td></tr>
					<tr><th><?php esc_html_e( 'Memory Limit', 'wp-sentinel-security' ); ?></th><td><?php echo esc_html( $env['php']['memory'] ?? '–' ); ?></td></tr>
					<tr>
						<th><?php esc_html_e( 'OPcache', 'wp-sentinel-security' ); ?></th>
						<td><?php echo ! empty( $env['php']['opcache'] ) ? '<span class="sentinel-badge sentinel-badge-low">' . esc_html__( 'Enabled', 'wp-sentinel-security' ) . '</span>' : '<span class="sentinel-badge sentinel-badge-medium">' . esc_html__( 'Disabled', 'wp-sentinel-security' ) . '</span>'; ?></td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'Redis', 'wp-sentinel-security' ); ?></th>
						<td><?php echo ! empty( $env['php']['redis'] ) ? esc_html__( 'Yes', 'wp-sentinel-security' ) : esc_html__( 'No', 'wp-sentinel-security' ); ?></td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'Memcached', 'wp-sentinel-security' ); ?></th>
						<td><?php echo ! empty( $env['php']['memcached'] ) ? esc_html__( 'Yes', 'wp-sentinel-security' ) : esc_html__( 'No', 'wp-sentinel-security' ); ?></td>
					</tr>
				</table>
			<?php else : ?>
				<p><?php esc_html_e( 'No data. Run an analysis first.', 'wp-sentinel-security' ); ?></p>
			<?php endif; ?>
		</div>

		<!-- Database -->
		<div class="sentinel-card">
			<h3><span class="dashicons dashicons-database"></span> <?php esc_html_e( 'Database', 'wp-sentinel-security' ); ?></h3>
			<?php if ( ! empty( $env['database'] ) ) : ?>
				<table class="sentinel-info-table">
					<tr><th><?php esc_html_e( 'Type', 'wp-sentinel-security' ); ?></th><td><?php echo esc_html( $env['database']['type'] ?? '–' ); ?></td></tr>
					<tr><th><?php esc_html_e( 'Version', 'wp-sentinel-security' ); ?></th><td><?php echo esc_html( $env['database']['version'] ?? '–' ); ?></td></tr>
					<tr><th><?php esc_html_e( 'Charset', 'wp-sentinel-security' ); ?></th><td><?php echo esc_html( $env['database']['charset'] ?? '–' ); ?></td></tr>
					<tr><th><?php esc_html_e( 'Table Prefix', 'wp-sentinel-security' ); ?></th><td><?php echo esc_html( $env['database']['prefix'] ?? '–' ); ?></td></tr>
				</table>
			<?php else : ?>
				<p><?php esc_html_e( 'No data. Run an analysis first.', 'wp-sentinel-security' ); ?></p>
			<?php endif; ?>
		</div>

		<!-- WordPress -->
		<div class="sentinel-card">
			<h3><span class="dashicons dashicons-wordpress"></span> <?php esc_html_e( 'WordPress', 'wp-sentinel-security' ); ?></h3>
			<?php if ( ! empty( $env['wordpress'] ) ) : ?>
				<table class="sentinel-info-table">
					<tr>
						<th><?php esc_html_e( 'Version', 'wp-sentinel-security' ); ?></th>
						<td>
							<?php echo esc_html( $env['wordpress']['version'] ?? '–' ); ?>
							<?php if ( empty( $env['wordpress']['is_latest'] ) ) : ?>
								<span class="sentinel-badge sentinel-badge-high"><?php esc_html_e( 'Update Available', 'wp-sentinel-security' ); ?></span>
							<?php else : ?>
								<span class="sentinel-badge sentinel-badge-low"><?php esc_html_e( 'Latest', 'wp-sentinel-security' ); ?></span>
							<?php endif; ?>
						</td>
					</tr>
					<tr><th><?php esc_html_e( 'Multisite', 'wp-sentinel-security' ); ?></th><td><?php echo ! empty( $env['wordpress']['multisite'] ) ? esc_html__( 'Yes', 'wp-sentinel-security' ) : esc_html__( 'No', 'wp-sentinel-security' ); ?></td></tr>
					<tr><th><?php esc_html_e( 'Active Plugins', 'wp-sentinel-security' ); ?></th><td><?php echo esc_html( $env['wordpress']['plugins'] ?? 0 ); ?></td></tr>
					<tr><th><?php esc_html_e( 'Active Theme', 'wp-sentinel-security' ); ?></th><td><?php echo esc_html( $env['wordpress']['theme'] ?? '–' ); ?></td></tr>
					<tr>
						<th><?php esc_html_e( 'Debug Mode', 'wp-sentinel-security' ); ?></th>
						<td><?php echo ! empty( $env['wordpress']['debug'] ) ? '<span class="sentinel-badge sentinel-badge-high">' . esc_html__( 'ON', 'wp-sentinel-security' ) . '</span>' : '<span class="sentinel-badge sentinel-badge-low">' . esc_html__( 'OFF', 'wp-sentinel-security' ) . '</span>'; ?></td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'SSL', 'wp-sentinel-security' ); ?></th>
						<td><?php echo ! empty( $env['wordpress']['ssl'] ) ? '<span class="sentinel-badge sentinel-badge-low">' . esc_html__( 'Yes', 'wp-sentinel-security' ) . '</span>' : '<span class="sentinel-badge sentinel-badge-high">' . esc_html__( 'No', 'wp-sentinel-security' ) . '</span>'; ?></td>
					</tr>
				</table>
			<?php else : ?>
				<p><?php esc_html_e( 'No data. Run an analysis first.', 'wp-sentinel-security' ); ?></p>
			<?php endif; ?>
		</div>

		<!-- Hosting -->
		<div class="sentinel-card">
			<h3><span class="dashicons dashicons-cloud"></span> <?php esc_html_e( 'Hosting', 'wp-sentinel-security' ); ?></h3>
			<?php if ( ! empty( $env['hosting'] ) ) : ?>
				<table class="sentinel-info-table">
					<tr><th><?php esc_html_e( 'Cloud Provider', 'wp-sentinel-security' ); ?></th><td><?php echo esc_html( $env['hosting']['cloud'] ?? '–' ); ?></td></tr>
					<tr><th><?php esc_html_e( 'cPanel', 'wp-sentinel-security' ); ?></th><td><?php echo ! empty( $env['hosting']['cpanel'] ) ? esc_html__( 'Yes', 'wp-sentinel-security' ) : esc_html__( 'No', 'wp-sentinel-security' ); ?></td></tr>
					<tr><th><?php esc_html_e( 'Plesk', 'wp-sentinel-security' ); ?></th><td><?php echo ! empty( $env['hosting']['plesk'] ) ? esc_html__( 'Yes', 'wp-sentinel-security' ) : esc_html__( 'No', 'wp-sentinel-security' ); ?></td></tr>
					<tr><th><?php esc_html_e( 'Docker', 'wp-sentinel-security' ); ?></th><td><?php echo ! empty( $env['hosting']['docker'] ) ? esc_html__( 'Yes', 'wp-sentinel-security' ) : esc_html__( 'No', 'wp-sentinel-security' ); ?></td></tr>
					<?php if ( ! empty( $env['hosting']['waf'] ) ) : ?>
						<tr>
							<th><?php esc_html_e( 'WAF', 'wp-sentinel-security' ); ?></th>
							<td>
								<?php
								$active_wafs = array_keys( array_filter( $env['hosting']['waf'] ) );
								echo $active_wafs ? esc_html( implode( ', ', array_map( 'ucfirst', $active_wafs ) ) ) : esc_html__( 'None detected', 'wp-sentinel-security' );
								?>
							</td>
						</tr>
					<?php endif; ?>
				</table>
			<?php else : ?>
				<p><?php esc_html_e( 'No data. Run an analysis first.', 'wp-sentinel-security' ); ?></p>
			<?php endif; ?>
		</div>

		<!-- Security Headers -->
		<div class="sentinel-card">
			<h3><span class="dashicons dashicons-lock"></span> <?php esc_html_e( 'Security Headers', 'wp-sentinel-security' ); ?></h3>
			<?php if ( ! empty( $sec_headers ) ) : ?>
				<table class="sentinel-info-table">
					<?php foreach ( $header_labels as $header => $label ) : ?>
						<tr>
							<th><?php echo esc_html( $label ); ?></th>
							<td>
								<?php if ( ! empty( $sec_headers[ $header ] ) ) : ?>
									<span class="sentinel-badge sentinel-badge-low">&#x2714; <?php esc_html_e( 'Present', 'wp-sentinel-security' ); ?></span>
								<?php else : ?>
									<span class="sentinel-badge sentinel-badge-high">&#x2718; <?php esc_html_e( 'Missing', 'wp-sentinel-security' ); ?></span>
								<?php endif; ?>
							</td>
						</tr>
					<?php endforeach; ?>
				</table>
			<?php else : ?>
				<p><?php esc_html_e( 'No data. Run an analysis first.', 'wp-sentinel-security' ); ?></p>
			<?php endif; ?>
		</div>

	</div><!-- .sentinel-grid -->

	<!-- Attack Surface Map -->
	<h2><?php esc_html_e( 'Attack Surface Map', 'wp-sentinel-security' ); ?></h2>

	<div class="sentinel-grid sentinel-grid-2">

		<!-- Public Files -->
		<div class="sentinel-card">
			<h3><?php esc_html_e( 'Public Sensitive Files', 'wp-sentinel-security' ); ?></h3>
			<?php if ( ! empty( $surface['public_files'] ) ) : ?>
				<table class="sentinel-table">
					<thead>
						<tr>
							<th><?php esc_html_e( 'File', 'wp-sentinel-security' ); ?></th>
							<th><?php esc_html_e( 'Status', 'wp-sentinel-security' ); ?></th>
							<th><?php esc_html_e( 'HTTP Code', 'wp-sentinel-security' ); ?></th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $surface['public_files'] as $file => $info ) : ?>
							<tr>
								<td><code><?php echo esc_html( $file ); ?></code></td>
								<td>
									<?php if ( $info['accessible'] ) : ?>
										<span class="sentinel-badge sentinel-badge-high">&#x2718; <?php esc_html_e( 'Accessible', 'wp-sentinel-security' ); ?></span>
									<?php else : ?>
										<span class="sentinel-badge sentinel-badge-low">&#x2714; <?php esc_html_e( 'Protected', 'wp-sentinel-security' ); ?></span>
									<?php endif; ?>
								</td>
								<td><?php echo esc_html( $info['http_code'] ); ?></td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			<?php else : ?>
				<p><?php esc_html_e( 'No data. Run an analysis first.', 'wp-sentinel-security' ); ?></p>
			<?php endif; ?>
		</div>

		<!-- User Enumeration & Login -->
		<div class="sentinel-card">
			<h3><?php esc_html_e( 'Login & User Enumeration', 'wp-sentinel-security' ); ?></h3>
			<?php if ( ! empty( $surface['login_endpoints'] ) || ! empty( $surface['user_enumeration'] ) ) : ?>
				<table class="sentinel-info-table">
					<?php if ( ! empty( $surface['login_endpoints'] ) ) : ?>
						<tr><th><?php esc_html_e( 'Login URL', 'wp-sentinel-security' ); ?></th><td><code><?php echo esc_html( $surface['login_endpoints']['login_url'] ?? '–' ); ?></code></td></tr>
						<tr>
							<th><?php esc_html_e( 'Registration Open', 'wp-sentinel-security' ); ?></th>
							<td>
								<?php if ( ! empty( $surface['login_endpoints']['registration_open'] ) ) : ?>
									<span class="sentinel-badge sentinel-badge-medium"><?php esc_html_e( 'Yes', 'wp-sentinel-security' ); ?></span>
								<?php else : ?>
									<span class="sentinel-badge sentinel-badge-low"><?php esc_html_e( 'No', 'wp-sentinel-security' ); ?></span>
								<?php endif; ?>
							</td>
						</tr>
					<?php endif; ?>
					<?php if ( ! empty( $surface['user_enumeration'] ) ) : ?>
						<tr>
							<th><?php esc_html_e( 'REST Users Exposed', 'wp-sentinel-security' ); ?></th>
							<td>
								<?php if ( $surface['user_enumeration']['rest_users_exposed'] ) : ?>
									<span class="sentinel-badge sentinel-badge-high">&#x2718; <?php esc_html_e( 'Yes', 'wp-sentinel-security' ); ?></span>
								<?php else : ?>
									<span class="sentinel-badge sentinel-badge-low">&#x2714; <?php esc_html_e( 'No', 'wp-sentinel-security' ); ?></span>
								<?php endif; ?>
							</td>
						</tr>
						<tr>
							<th><?php esc_html_e( 'Author Enumeration', 'wp-sentinel-security' ); ?></th>
							<td>
								<?php if ( $surface['user_enumeration']['author_enum_exposed'] ) : ?>
									<span class="sentinel-badge sentinel-badge-high">&#x2718; <?php esc_html_e( 'Exposed', 'wp-sentinel-security' ); ?></span>
								<?php else : ?>
									<span class="sentinel-badge sentinel-badge-low">&#x2714; <?php esc_html_e( 'Protected', 'wp-sentinel-security' ); ?></span>
								<?php endif; ?>
							</td>
						</tr>
					<?php endif; ?>
					<?php if ( ! empty( $surface['xmlrpc'] ) ) : ?>
						<tr>
							<th><?php esc_html_e( 'XML-RPC', 'wp-sentinel-security' ); ?></th>
							<td>
								<?php if ( $surface['xmlrpc']['enabled'] ) : ?>
									<span class="sentinel-badge sentinel-badge-medium"><?php esc_html_e( 'Enabled', 'wp-sentinel-security' ); ?></span>
								<?php else : ?>
									<span class="sentinel-badge sentinel-badge-low"><?php esc_html_e( 'Disabled', 'wp-sentinel-security' ); ?></span>
								<?php endif; ?>
							</td>
						</tr>
					<?php endif; ?>
				</table>
			<?php else : ?>
				<p><?php esc_html_e( 'No data. Run an analysis first.', 'wp-sentinel-security' ); ?></p>
			<?php endif; ?>
		</div>

		<!-- REST Endpoints -->
		<div class="sentinel-card">
			<h3><?php esc_html_e( 'REST API Endpoints', 'wp-sentinel-security' ); ?></h3>
			<?php if ( ! empty( $surface['rest_endpoints'] ) ) : ?>
				<p>
					<?php
					echo esc_html(
						sprintf(
							/* translators: %d: number of endpoints */
							__( '%d endpoints registered.', 'wp-sentinel-security' ),
							count( $surface['rest_endpoints'] )
						)
					);
					?>
				</p>
				<table class="sentinel-table">
					<thead>
						<tr>
							<th><?php esc_html_e( 'Route', 'wp-sentinel-security' ); ?></th>
							<th><?php esc_html_e( 'Methods', 'wp-sentinel-security' ); ?></th>
							<th><?php esc_html_e( 'Auth Required', 'wp-sentinel-security' ); ?></th>
						</tr>
					</thead>
					<tbody>
						<?php
						$endpoints_display = array_slice( $surface['rest_endpoints'], 0, 20 );
						foreach ( $endpoints_display as $endpoint ) :
							?>
							<tr>
								<td><code><?php echo esc_html( $endpoint['route'] ); ?></code></td>
								<td><?php echo esc_html( implode( ', ', $endpoint['methods'] ?? array() ) ); ?></td>
								<td>
									<?php if ( $endpoint['requires_auth'] ) : ?>
										<span class="sentinel-badge sentinel-badge-low"><?php esc_html_e( 'Yes', 'wp-sentinel-security' ); ?></span>
									<?php else : ?>
										<span class="sentinel-badge sentinel-badge-medium"><?php esc_html_e( 'No', 'wp-sentinel-security' ); ?></span>
									<?php endif; ?>
								</td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
				<?php if ( count( $surface['rest_endpoints'] ) > 20 ) : ?>
					<p class="description">
						<?php
						echo esc_html(
							sprintf(
								/* translators: %d: number of additional endpoints not shown */
								__( '+ %d more endpoints not shown.', 'wp-sentinel-security' ),
								count( $surface['rest_endpoints'] ) - 20
							)
						);
						?>
					</p>
				<?php endif; ?>
			<?php else : ?>
				<p><?php esc_html_e( 'No data. Run an analysis first.', 'wp-sentinel-security' ); ?></p>
			<?php endif; ?>
		</div>

		<!-- AJAX Actions -->
		<div class="sentinel-card">
			<h3><?php esc_html_e( 'Unauthenticated AJAX Actions', 'wp-sentinel-security' ); ?></h3>
			<?php if ( isset( $surface['ajax_actions'] ) ) : ?>
				<?php if ( ! empty( $surface['ajax_actions'] ) ) : ?>
					<p>
						<?php
						echo esc_html(
							sprintf(
								/* translators: %d: number of AJAX actions */
								__( '%d nopriv AJAX actions registered.', 'wp-sentinel-security' ),
								count( $surface['ajax_actions'] )
							)
						);
						?>
					</p>
					<ul class="sentinel-list">
						<?php foreach ( $surface['ajax_actions'] as $action ) : ?>
							<li><code><?php echo esc_html( $action ); ?></code></li>
						<?php endforeach; ?>
					</ul>
				<?php else : ?>
					<p><?php esc_html_e( 'No unauthenticated AJAX actions registered.', 'wp-sentinel-security' ); ?></p>
				<?php endif; ?>
			<?php else : ?>
				<p><?php esc_html_e( 'No data. Run an analysis first.', 'wp-sentinel-security' ); ?></p>
			<?php endif; ?>
		</div>

	</div><!-- .sentinel-grid -->

</div><!-- .sentinel-wrap -->

<script>
jQuery(function($) {
	$('#sentinel-run-intelligence').on('click', function() {
		var $btn = $(this);
		$btn.prop('disabled', true).text('<?php echo esc_js( __( 'Analyzing...', 'wp-sentinel-security' ) ); ?>');
		$('#sentinel-intelligence-notice').hide();

		$.post(sentinelData.ajaxUrl, {
			action : 'sentinel_run_intelligence',
			nonce  : sentinelData.nonces.intelligence
		}, function(response) {
			if (response.success) {
				$('#sentinel-intelligence-notice')
					.removeClass('notice-error')
					.addClass('notice notice-success')
					.html('<p><?php echo esc_js( __( 'Analysis complete! Reload the page to see updated data.', 'wp-sentinel-security' ) ); ?></p>')
					.show();
			} else {
				$('#sentinel-intelligence-notice')
					.removeClass('notice-success')
					.addClass('notice notice-error')
					.html('<p>' + (response.data.message || '<?php echo esc_js( __( 'Analysis failed. Please try again.', 'wp-sentinel-security' ) ); ?>') + '</p>')
					.show();
			}
		}).fail(function() {
			$('#sentinel-intelligence-notice')
				.removeClass('notice-success')
				.addClass('notice notice-error')
				.html('<p><?php echo esc_js( __( 'Analysis failed. Please try again.', 'wp-sentinel-security' ) ); ?></p>')
				.show();
		}).always(function() {
			$btn.prop('disabled', false).html('<span class="dashicons dashicons-update"></span> <?php echo esc_js( __( 'Run Fresh Analysis', 'wp-sentinel-security' ) ); ?>');
		});
	});
});
</script>
