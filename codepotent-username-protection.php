<?php

/**
 * -----------------------------------------------------------------------------
 * Plugin Name: Username Protection
 * Description: Prevent username enumeration and exposure through various common vectors.
 * Version: 1.0.0
 * Author: Code Potent
 * Author URI: https://codepotent.com
 * Plugin URI: https://codepotent.com/classicpress/plugins
 * Text Domain: codepotent-username-protection
 * Domain Path: /languages
 * -----------------------------------------------------------------------------
 * This is free software released under the terms of the General Public License,
 * version 2, or later. It is distributed WITHOUT ANY WARRANTY; without even the
 * implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. Full
 * text of the license is available at https://www.gnu.org/licenses/gpl-2.0.txt.
 * -----------------------------------------------------------------------------
 * Copyright 2020, Code Potent
 * -----------------------------------------------------------------------------
 *           ____          _      ____       _             _
 *          / ___|___   __| | ___|  _ \ ___ | |_ ___ _ __ | |_
 *         | |   / _ \ / _` |/ _ \ |_) / _ \| __/ _ \ '_ \| __|
 *         | |__| (_) | (_| |  __/  __/ (_) | ||  __/ | | | |_
 *          \____\___/ \__,_|\___|_|   \___/ \__\___|_| |_|\__|.com
 *
 * -----------------------------------------------------------------------------
 */

// Declare the namespace.
namespace CodePotent\UsernameProtection;

// Prevent direct access.
if (!defined('ABSPATH')) {
	die();
}

/**
 * Username Protection
 *
 * A class to prevent username disclosure in a number of ways:
 *
 * 	1) prevent anon access to usernames via REST endpoints
 * 	2) prevent display names in feeds
 * 	3) prevent username in author archive URL
 * 	4) prevent username discovery via author ID enumeration
 * 	5) prevent display name discovery of comment authors
 *
 *
 * @author John Alarcon
 *
 * @since 0.1.0
 */
class UsernameProtection {

	/**
	 * A simple constructor fights gas and bloating!
	 *
	 * @author John Alarcon
	 *
	 * @since 1.0.0
	 *
	 * @return void
	 */
	public function __construct() {

		// Run the plugin code.
		$this->init();

	}

	/**
	 * Hook into the system.
	 *
	 * Setup actions and filters used by the plugin.
	 *
	 * @author John Alarcon
	 *
	 * @since 1.0.0
	 *
	 * @return void
	 */
	public function init() {

		// Load update client.
		require_once(plugin_dir_path(__FILE__).'classes/UpdateClient.class.php');

		// Prevent leaks in author id enumeration redirects.
		add_filter('redirect_canonical', [$this, 'filter_author_archive_redirects'], 10, 2);

		// Prevent leaks in author archive URLs.
		add_filter('author_link', [$this, 'filter_author_url'], 10, 2);

		// Prevent leaks in feeds.
		add_filter('the_author', [$this, 'filter_feeds'], PHP_INT_MAX, 1);
		add_filter('comment_author_rss', [$this, 'filter_feeds'], PHP_INT_MAX, 1);

		// Prevent leaks in comments.
		add_filter('get_comment_author', [$this, 'filter_comments']);

		// Prevent leaks in REST requests.
		add_filter('rest_authentication_errors', [$this, 'prevent_anonymous_username_enumeration']);

		// Prevent leaks in failed login attempts.
		add_filter('login_errors', [$this, 'filter_login_errors']);

	}

	/**
	 * Filter author id enumeration redirecs.
	 *
	 * With short URLs enabled, requests like https://www.yoursite.com/?author=1
	 * redirect to the author archive for the user of that id. The resulting URL
	 * exposes the username. To prevent this, the redirection is canceled if the
	 * request contains the author argument.
	 *
	 * @author John Alarcon
	 *
	 * @since 1.0.0
	 *
	 * @param string $redirect Redirect target URL.
	 * @param string $request Original requesting URL.
	 *
	 * @return void|string The raw or short url.
	 */
	public function filter_author_archive_redirects($redirect, $request) {

		// If user is logged in, no need to change anything.
		if (is_user_logged_in()) {
			return $redirect;
		}

		// Is this an author request? Cancel the redirect.
		if (preg_match('/author=([0-9]*)(\/*)/i', $request)) {
			return;
		}

		// Perform any other redirects as usual.
		return $redirect;

	}

	/**
	 * Filter author URL.
	 *
	 * This filter ensures that generated author archive URLs are "raw" even for
	 * sites that have short URLs enabled. Prevents username leaks in the author
	 * archive URLs.
	 *
	 * @author John Alarcon
	 *
	 * @since 1.0.0
	 *
	 * @param string $archive_url System-generated URL to author archive.
	 * @param integer $user_id Author ID.
	 *
	 * @return string https://yoursite.com/?author=1
	 */
	public function filter_author_url($archive_url, $user_id) {

		// If user is logged in, no need to hide anything.
		if (is_user_logged_in()) {
			return $archive_url;
		}

		// Anonymous users get the direct URL; no username.
		return get_bloginfo('wpurl').'/?author='.$user_id;

	}

	/**
	 * Filter display names from feeds.
	 *
	 * The feeds created by ClassicPress expose users' "display names". Although
	 * not in all cases, it is possible to extrapolate the username based on the
	 * display name. This filter replaces display names with the site title.
	 *
	 * 	...so, this...
	 *
	 * 			<dc:creator><![CDATA[Jane Smith]]></dc:creator>
	 *
	 * 	...becomes this...
	 *
	 * 			<dc:creator><![CDATA[Your Site Title]]></dc:creator>
	 *
	 * 	...and it applies to all of the following types of requests:
	 *
	 *  		/feed/
	 * 			/category/categorynamehere/feed/
	 * 			/tag/tagnamehere/feed/
	 * 			/2016/11/feed/
	 * 			/2016/11/8/feed/
	 * 			/2016/feed/
	 * 			/search/searchtermhere/feed
	 * 			/comments/feed
	 *
	 * @author John Alarcon
	 *
	 * @since 1.0.0
	 *
	 * @param string $display_name
	 *
	 * @return string
	 */
	public function filter_feeds($display_name) {

		// If user is logged in, no need to change anything.
		if (is_user_logged_in()) {
			return $display_name;
		}

		// Remove usernames from feeds.
		return apply_filters('codepotent_username_protection_feeds', get_bloginfo('name'));

	}

	/**
	 * Filter comment display names.
	 *
	 * This method replaces the display names on all comments. Note that this is
	 * a filter for the core ClassicPress comments; it has no affect on external
	 * commenting systems.
	 *
	 * @author John Alarcon
	 *
	 * @since 1.0.0
	 *
	 * @param string $author Display name of the commenter.
	 *
	 * @return string Altered or unaltered display name.
	 */
	public function filter_comments($comment_author) {

		// If user logged in, no need to change anything.
		if (is_user_logged_in()) {
			return $comment_author;
		}

		// Replace the username.
		return apply_filters('codepotent_username_protection_comments', esc_html__('Comment', 'codepotent-username-protection'));

	}

	/**
	 * Filter login errors.
	 *
	 * This method replaces login error texts with a text that is less descript.
	 * This prevents valid usernames from being confirmed.
	 *
	 * @author John Alarcon
	 *
	 * @since 1.0.0
	 *
	 * @param string $error_text The default error text.
	 *
	 * @return string The amended error text.
	 */
	public function filter_login_errors($error_text) {

		// Replace the error text.
		return apply_filters('codepotent_username_protection_login_errors', esc_html__('Login failed. Please try again.', 'codepotent-username-protection'));

	}

	/**
	 * Prevent anonymous access to usernames.
	 *
	 * This method runs a series of successive checks to find out whether or not
	 * the user can access usernames via the REST API. If so, the method returns
	 * early. If not, the method runs to completion and quits.
	 *
	 * @author John Alarcon
	 *
	 * @since 1.0.0
	 *
	 * @return void
	 */
	public function prevent_anonymous_username_enumeration() {

		// If not the users endpoint, no need to block access.
		if (!strstr($_SERVER['REQUEST_URI'], 'wp/v2/users')) {
			return;
		}

		// If posts endpoint, WITHOUT _embed argument, no need to block access.
		if (strstr($_SERVER['REQUEST_URI'], 'wp/v2/posts')) {
			if (!isset($_REQUEST['_embed'])) {
				return;
			}
		}

		// If user is logged in, *probably* no need to block access.
		if (is_user_logged_in()) {
			return;
		}

		// If user is admin, no need to block access.
		if (current_user_can('manage_options')) {
			return;
		}

		// If here, block access. No REST for the wicked!
		return new \WP_Error(
			'rest_no_route',
			esc_html__('No route was found matching the URL and request method', 'codepotent-username-protection'),
			['status' => 404]
		);

	}

}

// Armor all the usernames!

// Armor all the usernames!
new UsernameProtection;