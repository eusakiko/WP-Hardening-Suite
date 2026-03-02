<?php
/**
 * Reusable admin navigation header partial.
 *
 * @package WP_Sentinel_Security
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$current_page = isset( $_GET['page'] ) ? sanitize_text_field( wp_unslash( $_GET['page'] ) ) : 'sentinel-security'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended

$nav_items = array(
	'sentinel-security'      => __( 'Dashboard', 'wp-sentinel-security' ),
	'sentinel-scanner'       => __( 'Scanner', 'wp-sentinel-security' ),
	'sentinel-hardening'     => __( 'Hardening', 'wp-sentinel-security' ),
	'sentinel-backups'       => __( 'Backups', 'wp-sentinel-security' ),
	'sentinel-reports'       => __( 'Reports', 'wp-sentinel-security' ),
	'sentinel-alerts'        => __( 'Alerts', 'wp-sentinel-security' ),
	'sentinel-activity'      => __( 'Activity', 'wp-sentinel-security' ),
	'sentinel-intelligence'  => __( 'Intelligence', 'wp-sentinel-security' ),
	'sentinel-settings'      => __( 'Settings', 'wp-sentinel-security' ),
);
?>

<nav class="sentinel-nav-header">
	<div class="sentinel-nav-brand">
		<span class="dashicons dashicons-shield-alt"></span>
		<strong><?php esc_html_e( 'Sentinel', 'wp-sentinel-security' ); ?></strong>
	</div>
	<ul class="sentinel-nav-tabs">
		<?php foreach ( $nav_items as $slug => $label ) : ?>
			<li>
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=' . $slug ) ); ?>"
				   class="sentinel-nav-tab<?php echo $current_page === $slug ? ' sentinel-nav-tab-active' : ''; ?>">
					<?php echo esc_html( $label ); ?>
				</a>
			</li>
		<?php endforeach; ?>
	</ul>
</nav>
