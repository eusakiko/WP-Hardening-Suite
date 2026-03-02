<?php
/**
 * Two-Factor Authentication (TOTP).
 *
 * Provides TOTP-based two-factor authentication for WordPress users.
 * Generates secrets, validates OTP codes, and manages per-user 2FA state
 * via user meta. Hooks into the WordPress login flow to enforce 2FA
 * when enabled for a user.
 *
 * @package WP_Sentinel_Security
 * @since   2.1.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Two_Factor_Auth
 */
class Two_Factor_Auth {

	/**
	 * Plugin settings.
	 *
	 * @var array
	 */
	private $settings;

	/**
	 * TOTP period in seconds.
	 *
	 * @var int
	 */
	const PERIOD = 30;

	/**
	 * Number of digits in a TOTP code.
	 *
	 * @var int
	 */
	const DIGITS = 6;

	/**
	 * Base32 character set.
	 *
	 * @var string
	 */
	const BASE32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

	/**
	 * User meta key for the TOTP secret.
	 *
	 * @var string
	 */
	const META_SECRET = 'sentinel_2fa_secret';

	/**
	 * User meta key for 2FA enabled state.
	 *
	 * @var string
	 */
	const META_ENABLED = 'sentinel_2fa_enabled';

	/**
	 * User meta key for recovery codes.
	 *
	 * @var string
	 */
	const META_RECOVERY = 'sentinel_2fa_recovery';

	/**
	 * Constructor.
	 *
	 * @param array $settings Plugin settings.
	 */
	public function __construct( $settings = array() ) {
		$this->settings = $settings;
	}

	/**
	 * Initialize — register WordPress hooks for 2FA login flow.
	 *
	 * @return void
	 */
	public function init() {
		add_action( 'wp_login', array( $this, 'handle_login' ), 10, 2 );
		add_action( 'login_form_sentinel_2fa', array( $this, 'render_2fa_form' ) );
		add_action( 'admin_init', array( $this, 'register_user_settings' ) );
	}

	/**
	 * Generate a random Base32-encoded TOTP secret.
	 *
	 * @param int $length Number of characters in the secret (default 16).
	 * @return string Base32-encoded secret.
	 */
	public function generate_secret( $length = 16 ) {
		$secret = '';
		$chars  = self::BASE32_CHARS;
		$max    = strlen( $chars ) - 1;

		for ( $i = 0; $i < $length; $i++ ) {
			$secret .= $chars[ random_int( 0, $max ) ];
		}

		return $secret;
	}

	/**
	 * Generate a TOTP code for a given secret and time step.
	 *
	 * Implements RFC 6238 TOTP using HMAC-SHA1.
	 *
	 * @param string   $secret Base32-encoded secret.
	 * @param int|null $time   Unix timestamp (default: current time).
	 * @return string Zero-padded TOTP code.
	 */
	public function get_code( $secret, $time = null ) {
		if ( null === $time ) {
			$time = time();
		}

		$time_step = (int) floor( $time / self::PERIOD );
		$binary    = $this->base32_decode( $secret );

		// Pack time as 64-bit big-endian.
		$time_bytes = pack( 'N*', 0, $time_step );

		$hash   = hash_hmac( 'sha1', $time_bytes, $binary, true );
		$offset = ord( $hash[ strlen( $hash ) - 1 ] ) & 0x0F;

		$code = (
			( ( ord( $hash[ $offset ] ) & 0x7F ) << 24 ) |
			( ( ord( $hash[ $offset + 1 ] ) & 0xFF ) << 16 ) |
			( ( ord( $hash[ $offset + 2 ] ) & 0xFF ) << 8 ) |
			( ord( $hash[ $offset + 3 ] ) & 0xFF )
		) % pow( 10, self::DIGITS );

		return str_pad( (string) $code, self::DIGITS, '0', STR_PAD_LEFT );
	}

	/**
	 * Verify a TOTP code against a secret.
	 *
	 * Allows a ±1 time-step window to account for clock skew.
	 *
	 * @param string $secret Base32-encoded secret.
	 * @param string $code   The TOTP code to verify.
	 * @param int    $window Number of adjacent time steps to accept (default 1).
	 * @return bool True if the code is valid.
	 */
	public function verify_code( $secret, $code, $window = 1 ) {
		if ( strlen( $code ) !== self::DIGITS ) {
			return false;
		}

		$now = time();

		for ( $i = -$window; $i <= $window; $i++ ) {
			$check_time = $now + ( $i * self::PERIOD );
			if ( hash_equals( $this->get_code( $secret, $check_time ), $code ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Generate recovery codes for a user.
	 *
	 * @param int $count Number of recovery codes (default 8).
	 * @return string[] Array of recovery code strings.
	 */
	public function generate_recovery_codes( $count = 8 ) {
		$codes = array();
		for ( $i = 0; $i < $count; $i++ ) {
			$codes[] = strtoupper( bin2hex( random_bytes( 4 ) ) );
		}
		return $codes;
	}

	/**
	 * Enable 2FA for a user: store the secret and recovery codes.
	 *
	 * @param int    $user_id User ID.
	 * @param string $secret  Base32-encoded TOTP secret.
	 * @return string[] Recovery codes.
	 */
	public function enable_for_user( $user_id, $secret ) {
		$recovery_codes = $this->generate_recovery_codes();

		update_user_meta( $user_id, self::META_SECRET, $secret );
		update_user_meta( $user_id, self::META_ENABLED, '1' );

		$hashed_codes = array();
		foreach ( $recovery_codes as $code ) {
			$hashed_codes[] = wp_hash( $code );
		}
		update_user_meta( $user_id, self::META_RECOVERY, wp_json_encode( $hashed_codes ) );

		return $recovery_codes;
	}

	/**
	 * Disable 2FA for a user.
	 *
	 * @param int $user_id User ID.
	 * @return void
	 */
	public function disable_for_user( $user_id ) {
		delete_user_meta( $user_id, self::META_SECRET );
		delete_user_meta( $user_id, self::META_ENABLED );
		delete_user_meta( $user_id, self::META_RECOVERY );
	}

	/**
	 * Check whether 2FA is enabled for a given user.
	 *
	 * @param int $user_id User ID.
	 * @return bool True if 2FA is enabled.
	 */
	public function is_enabled_for_user( $user_id ) {
		return '1' === get_user_meta( $user_id, self::META_ENABLED, true );
	}

	/**
	 * Build a TOTP provisioning URI for QR code generation.
	 *
	 * Compatible with Google Authenticator, Authy, etc.
	 *
	 * @param string $secret     Base32-encoded secret.
	 * @param string $user_email User email for identification.
	 * @return string otpauth:// URI.
	 */
	public function get_provisioning_uri( $secret, $user_email ) {
		$issuer = rawurlencode( get_bloginfo( 'name' ) );
		$label  = rawurlencode( $user_email );

		return sprintf(
			'otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=%d&period=%d',
			$issuer,
			$label,
			$secret,
			$issuer,
			self::DIGITS,
			self::PERIOD
		);
	}

	/**
	 * Handle login — redirect to 2FA prompt if enabled for the user.
	 *
	 * Hooked to 'wp_login' action.
	 *
	 * @param string   $user_login Username.
	 * @param \WP_User $user       WP_User object.
	 * @return void
	 */
	public function handle_login( $user_login, $user ) {
		if ( ! $this->is_enabled_for_user( $user->ID ) ) {
			return;
		}

		// Log user out temporarily and redirect to 2FA form.
		wp_clear_auth_cookie();

		$token = wp_hash( $user->ID . '|' . time() );
		set_transient( 'sentinel_2fa_' . $token, $user->ID, 5 * MINUTE_IN_SECONDS );

		$redirect_url = add_query_arg(
			array(
				'action'         => 'sentinel_2fa',
				'sentinel_token' => rawurlencode( $token ),
			),
			wp_login_url()
		);

		wp_safe_redirect( $redirect_url );
		exit;
	}

	/**
	 * Render the 2FA verification form on the login page.
	 *
	 * @return void
	 */
	public function render_2fa_form() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$token   = isset( $_REQUEST['sentinel_token'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['sentinel_token'] ) ) : '';
		$user_id = get_transient( 'sentinel_2fa_' . $token );

		if ( ! $user_id ) {
			wp_safe_redirect( wp_login_url() );
			exit;
		}

		// Process submitted code.
		if ( 'POST' === $_SERVER['REQUEST_METHOD'] ) {
			check_admin_referer( 'sentinel_2fa_verify' );

			$code = isset( $_POST['sentinel_2fa_code'] ) ? sanitize_text_field( wp_unslash( $_POST['sentinel_2fa_code'] ) ) : '';

			$secret = get_user_meta( $user_id, self::META_SECRET, true );
			$valid  = $this->verify_code( $secret, $code );

			// Check recovery codes if TOTP fails.
			if ( ! $valid ) {
				$valid = $this->verify_recovery_code( $user_id, $code );
			}

			if ( $valid ) {
				delete_transient( 'sentinel_2fa_' . $token );

				$user = get_user_by( 'id', $user_id );
				wp_set_auth_cookie( $user_id, false );
				do_action( 'wp_login', $user->user_login, $user );

				wp_safe_redirect( admin_url() );
				exit;
			}

			$error = __( 'Invalid verification code. Please try again.', 'wp-sentinel-security' );
		}

		// Render form.
		login_header( __( 'Two-Factor Authentication', 'wp-sentinel-security' ) );
		?>
		<form name="sentinel_2fa_form" id="sentinel_2fa_form" method="post">
			<?php wp_nonce_field( 'sentinel_2fa_verify' ); ?>
			<input type="hidden" name="sentinel_token" value="<?php echo esc_attr( $token ); ?>" />

			<?php if ( ! empty( $error ) ) : ?>
				<div id="login_error"><strong><?php echo esc_html( $error ); ?></strong></div>
			<?php endif; ?>

			<p><?php esc_html_e( 'Enter the code from your authenticator app, or a recovery code.', 'wp-sentinel-security' ); ?></p>

			<p>
				<label for="sentinel_2fa_code"><?php esc_html_e( 'Authentication Code', 'wp-sentinel-security' ); ?></label>
				<input type="text" name="sentinel_2fa_code" id="sentinel_2fa_code"
					class="input" size="20" autocomplete="one-time-code" autofocus="autofocus"
					pattern="[0-9A-Za-z]*" inputmode="numeric" />
			</p>

			<p class="submit">
				<input type="submit" name="wp-submit" id="wp-submit"
					class="button button-primary button-large"
					value="<?php esc_attr_e( 'Verify', 'wp-sentinel-security' ); ?>" />
			</p>
		</form>
		<?php
		login_footer();
		exit;
	}

	/**
	 * Register user profile settings for 2FA management.
	 *
	 * @return void
	 */
	public function register_user_settings() {
		add_action( 'show_user_profile', array( $this, 'render_user_profile_field' ) );
		add_action( 'edit_user_profile', array( $this, 'render_user_profile_field' ) );
		add_action( 'personal_options_update', array( $this, 'save_user_profile_field' ) );
	}

	/**
	 * Render 2FA toggle on user profile page.
	 *
	 * @param \WP_User $user User object.
	 * @return void
	 */
	public function render_user_profile_field( $user ) {
		?>
		<h3><?php esc_html_e( 'Two-Factor Authentication', 'wp-sentinel-security' ); ?></h3>
		<table class="form-table">
			<tr>
				<th scope="row"><?php esc_html_e( '2FA Status', 'wp-sentinel-security' ); ?></th>
				<td>
					<?php if ( $this->is_enabled_for_user( $user->ID ) ) : ?>
						<p><strong><?php esc_html_e( 'Enabled', 'wp-sentinel-security' ); ?></strong></p>
						<label>
							<input type="checkbox" name="sentinel_disable_2fa" value="1" />
							<?php esc_html_e( 'Disable two-factor authentication', 'wp-sentinel-security' ); ?>
						</label>
					<?php else : ?>
						<label>
							<input type="checkbox" name="sentinel_enable_2fa" value="1" />
							<?php esc_html_e( 'Enable two-factor authentication', 'wp-sentinel-security' ); ?>
						</label>
					<?php endif; ?>
				</td>
			</tr>
		</table>
		<?php
	}

	/**
	 * Save 2FA preference from user profile.
	 *
	 * @param int $user_id User ID.
	 * @return void
	 */
	public function save_user_profile_field( $user_id ) {
		if ( ! current_user_can( 'edit_user', $user_id ) ) {
			return;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( ! empty( $_POST['sentinel_enable_2fa'] ) ) {
			$secret         = $this->generate_secret();
			$recovery_codes = $this->enable_for_user( $user_id, $secret );
			set_transient( 'sentinel_2fa_setup_' . $user_id, array(
				'secret'         => $secret,
				'recovery_codes' => $recovery_codes,
			), 5 * MINUTE_IN_SECONDS );
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( ! empty( $_POST['sentinel_disable_2fa'] ) ) {
			$this->disable_for_user( $user_id );
		}
	}

	/**
	 * Verify a recovery code for a user.
	 *
	 * Recovery codes are single-use: once matched, the code is removed.
	 *
	 * @param int    $user_id User ID.
	 * @param string $code    Recovery code to verify.
	 * @return bool True if valid.
	 */
	private function verify_recovery_code( $user_id, $code ) {
		$stored = get_user_meta( $user_id, self::META_RECOVERY, true );
		if ( empty( $stored ) ) {
			return false;
		}

		$hashes = json_decode( $stored, true );
		if ( ! is_array( $hashes ) ) {
			return false;
		}

		$code_hash = wp_hash( strtoupper( $code ) );

		foreach ( $hashes as $index => $hash ) {
			if ( hash_equals( $hash, $code_hash ) ) {
				// Remove used code.
				unset( $hashes[ $index ] );
				update_user_meta( $user_id, self::META_RECOVERY, wp_json_encode( array_values( $hashes ) ) );
				return true;
			}
		}

		return false;
	}

	/**
	 * Decode a Base32-encoded string.
	 *
	 * @param string $input Base32 string.
	 * @return string Binary data.
	 */
	private function base32_decode( $input ) {
		$input  = strtoupper( $input );
		$buffer = 0;
		$bits   = 0;
		$output = '';

		for ( $i = 0, $len = strlen( $input ); $i < $len; $i++ ) {
			$val = strpos( self::BASE32_CHARS, $input[ $i ] );
			if ( false === $val ) {
				continue;
			}
			$buffer = ( $buffer << 5 ) | $val;
			$bits  += 5;
			if ( $bits >= 8 ) {
				$bits   -= 8;
				$output .= chr( ( $buffer >> $bits ) & 0xFF );
			}
		}

		return $output;
	}
}
