<?php
/**
 * Settings view.
 *
 * @package WP_Sentinel_Security
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

require SENTINEL_PLUGIN_DIR . 'admin/views/partials/header.php';

$settings = get_option( 'sentinel_settings', array() );
$defaults = array(
	'scan_frequency'       => 'daily',
	'backup_before_action' => true,
	'alert_email'          => get_option( 'admin_email' ),
	'alert_channels'       => array( 'email' ),
	'log_retention_days'   => 90,
	'async_scanning'       => true,
	'wpscan_api_key'       => '',
	'slack_webhook'        => '',
	'telegram_bot_token'   => '',
	'telegram_chat_id'     => '',
	'company_name'         => get_option( 'blogname' ),
	'company_logo'         => '',
);
$settings = wp_parse_args( $settings, $defaults );
?>

<div class="wrap sentinel-wrap">

	<div class="sentinel-page-header">
		<div class="sentinel-header-left">
			<span class="dashicons dashicons-admin-settings sentinel-header-icon"></span>
			<h1><?php esc_html_e( 'Settings', 'wp-sentinel-security' ); ?></h1>
		</div>
	</div>

	<form method="post" action="options.php">
		<?php settings_fields( 'sentinel_settings_group' ); ?>

		<!-- General Settings -->
		<div class="sentinel-card">
			<h2><?php esc_html_e( 'General Settings', 'wp-sentinel-security' ); ?></h2>
			<table class="form-table">
				<tr>
					<th scope="row">
						<label for="sentinel_scan_frequency"><?php esc_html_e( 'Scan Frequency', 'wp-sentinel-security' ); ?></label>
					</th>
					<td>
						<select name="sentinel_settings[scan_frequency]" id="sentinel_scan_frequency">
							<option value="hourly" <?php selected( $settings['scan_frequency'], 'hourly' ); ?>><?php esc_html_e( 'Hourly', 'wp-sentinel-security' ); ?></option>
							<option value="twicedaily" <?php selected( $settings['scan_frequency'], 'twicedaily' ); ?>><?php esc_html_e( 'Twice Daily', 'wp-sentinel-security' ); ?></option>
							<option value="daily" <?php selected( $settings['scan_frequency'], 'daily' ); ?>><?php esc_html_e( 'Daily', 'wp-sentinel-security' ); ?></option>
							<option value="weekly" <?php selected( $settings['scan_frequency'], 'weekly' ); ?>><?php esc_html_e( 'Weekly', 'wp-sentinel-security' ); ?></option>
						</select>
					</td>
				</tr>
				<tr>
					<th scope="row">
						<label for="sentinel_backup_before_action"><?php esc_html_e( 'Backup Before Action', 'wp-sentinel-security' ); ?></label>
					</th>
					<td>
						<input type="checkbox" name="sentinel_settings[backup_before_action]" id="sentinel_backup_before_action" value="1" <?php checked( $settings['backup_before_action'] ); ?> />
						<label for="sentinel_backup_before_action"><?php esc_html_e( 'Create a backup before applying any security fix', 'wp-sentinel-security' ); ?></label>
					</td>
				</tr>
				<tr>
					<th scope="row">
						<label for="sentinel_log_retention"><?php esc_html_e( 'Log Retention (days)', 'wp-sentinel-security' ); ?></label>
					</th>
					<td>
						<input type="number" name="sentinel_settings[log_retention_days]" id="sentinel_log_retention" value="<?php echo esc_attr( $settings['log_retention_days'] ); ?>" min="1" max="365" class="small-text" />
					</td>
				</tr>
				<tr>
					<th scope="row">
						<label for="sentinel_async_scanning"><?php esc_html_e( 'Async Scanning', 'wp-sentinel-security' ); ?></label>
					</th>
					<td>
						<input type="checkbox" name="sentinel_settings[async_scanning]" id="sentinel_async_scanning" value="1" <?php checked( $settings['async_scanning'] ); ?> />
						<label for="sentinel_async_scanning"><?php esc_html_e( 'Run scans asynchronously (recommended)', 'wp-sentinel-security' ); ?></label>
					</td>
				</tr>
			</table>
		</div>

		<!-- API Keys -->
		<div class="sentinel-card">
			<h2><?php esc_html_e( 'API Keys', 'wp-sentinel-security' ); ?></h2>
			<table class="form-table">
				<tr>
					<th scope="row">
						<label for="sentinel_wpscan_api_key"><?php esc_html_e( 'WPScan API Key', 'wp-sentinel-security' ); ?></label>
					</th>
					<td>
						<input type="password" name="sentinel_settings[wpscan_api_key]" id="sentinel_wpscan_api_key" value="<?php echo esc_attr( $settings['wpscan_api_key'] ); ?>" class="regular-text" autocomplete="off" />
						<p class="description">
							<?php
							printf(
								/* translators: %s: WPScan website URL */
								esc_html__( 'Get a free API key from %s', 'wp-sentinel-security' ),
								'<a href="https://wpscan.com/" target="_blank" rel="noopener noreferrer">wpscan.com</a>'
							);
							?>
						</p>
					</td>
				</tr>
			</table>
		</div>

		<!-- Alert Settings -->
		<div class="sentinel-card">
			<h2><?php esc_html_e( 'Alert Settings', 'wp-sentinel-security' ); ?></h2>
			<table class="form-table">
				<tr>
					<th scope="row">
						<label for="sentinel_alert_email"><?php esc_html_e( 'Alert Email', 'wp-sentinel-security' ); ?></label>
					</th>
					<td>
						<input type="email" name="sentinel_settings[alert_email]" id="sentinel_alert_email" value="<?php echo esc_attr( $settings['alert_email'] ); ?>" class="regular-text" />
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Alert Channels', 'wp-sentinel-security' ); ?></th>
					<td>
						<label>
							<input type="checkbox" name="sentinel_settings[alert_channels][]" value="email" <?php checked( in_array( 'email', (array) $settings['alert_channels'], true ) ); ?> />
							<?php esc_html_e( 'Email', 'wp-sentinel-security' ); ?>
						</label><br />
						<label>
							<input type="checkbox" name="sentinel_settings[alert_channels][]" value="slack" <?php checked( in_array( 'slack', (array) $settings['alert_channels'], true ) ); ?> />
							<?php esc_html_e( 'Slack', 'wp-sentinel-security' ); ?>
						</label><br />
						<label>
							<input type="checkbox" name="sentinel_settings[alert_channels][]" value="telegram" <?php checked( in_array( 'telegram', (array) $settings['alert_channels'], true ) ); ?> />
							<?php esc_html_e( 'Telegram', 'wp-sentinel-security' ); ?>
						</label>
					</td>
				</tr>
				<tr>
					<th scope="row">
						<label for="sentinel_slack_webhook"><?php esc_html_e( 'Slack Webhook URL', 'wp-sentinel-security' ); ?></label>
					</th>
					<td>
						<input type="url" name="sentinel_settings[slack_webhook]" id="sentinel_slack_webhook" value="<?php echo esc_attr( $settings['slack_webhook'] ); ?>" class="regular-text" />
					</td>
				</tr>
				<tr>
					<th scope="row">
						<label for="sentinel_telegram_bot_token"><?php esc_html_e( 'Telegram Bot Token', 'wp-sentinel-security' ); ?></label>
					</th>
					<td>
						<input type="password" name="sentinel_settings[telegram_bot_token]" id="sentinel_telegram_bot_token" value="<?php echo esc_attr( $settings['telegram_bot_token'] ); ?>" class="regular-text" autocomplete="off" />
					</td>
				</tr>
				<tr>
					<th scope="row">
						<label for="sentinel_telegram_chat_id"><?php esc_html_e( 'Telegram Chat ID', 'wp-sentinel-security' ); ?></label>
					</th>
					<td>
						<input type="text" name="sentinel_settings[telegram_chat_id]" id="sentinel_telegram_chat_id" value="<?php echo esc_attr( $settings['telegram_chat_id'] ); ?>" class="regular-text" />
					</td>
				</tr>
			</table>
		</div>

		<!-- Branding -->
		<div class="sentinel-card">
			<h2><?php esc_html_e( 'Branding', 'wp-sentinel-security' ); ?></h2>
			<table class="form-table">
				<tr>
					<th scope="row">
						<label for="sentinel_company_name"><?php esc_html_e( 'Company Name', 'wp-sentinel-security' ); ?></label>
					</th>
					<td>
						<input type="text" name="sentinel_settings[company_name]" id="sentinel_company_name" value="<?php echo esc_attr( $settings['company_name'] ); ?>" class="regular-text" />
					</td>
				</tr>
				<tr>
					<th scope="row">
						<label for="sentinel_company_logo"><?php esc_html_e( 'Company Logo URL', 'wp-sentinel-security' ); ?></label>
					</th>
					<td>
						<input type="url" name="sentinel_settings[company_logo]" id="sentinel_company_logo" value="<?php echo esc_attr( $settings['company_logo'] ); ?>" class="regular-text" />
					</td>
				</tr>
			</table>
		</div>

		<?php submit_button( __( 'Save Settings', 'wp-sentinel-security' ) ); ?>

	</form>

</div>
