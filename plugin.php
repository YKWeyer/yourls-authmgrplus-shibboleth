<?php
/*
Plugin Name: Shibboleth for AuthMgrPlus
Plugin URI: https://github.com/YKWeyer/yourls-authmgrplus-shibboleth
Description: Extends YOURLS AuthMgrPlus plugin to add Shibboleth compatibility
Version: 1.0
Author: Yann Weyer
Author URI: https://github.com/YKWeyer
*/

// No direct call
if( !defined( 'YOURLS_ABSPATH' ) ) die();

if (!defined('SHIBBOLETH_UID'))
        define('SHIBBOLETH_UID', 'cn');
if (!defined('SHIBBOLETH_ENTITLEMENT'))
        define('SHIBBOLETH_ENTITLEMENT', 'entitlement');
if (!defined('SHIBBOLETH_ENTITLEMENT_REGEX'))
        define('SHIBBOLETH_ENTITLEMENT_REGEX', '/^.*urn:mace:dir:entitlement:yourls.local:.*$/');
if (!defined('SHIBBOLETH_LOGOUT_URL'))
        define('SHIBBOLETH_LOGOUT_URL', '/Shibboleth.sso/Logout');

/***
 * Utility functions to get uid and entitlement, even if APACHE prepends `REDIRECT_` to it
 */
function shibboleth_get_uid()
{
    return $_SERVER[SHIBBOLETH_UID] ?? $_SERVER['REDIRECT_' . SHIBBOLETH_UID];
}

function shibboleth_get_entitlement()
{
    return $_SERVER[SHIBBOLETH_ENTITLEMENT] ?? $_SERVER['REDIRECT_' . SHIBBOLETH_ENTITLEMENT];
}

/**
 * Ensure the AuthMgrPlus plugin is installed and active (display an error and deactivate Shibboleth plugin if not)
 */
yourls_add_filter('admin_init', 'shibboleth_check_authMgrPlus');
function shibboleth_check_authMgrPlus()
{
    $activePlugins = yourls_get_option( 'active_plugins' );
    if(!in_array('authMgrPlus/plugin.php', $activePlugins)){
        yourls_add_notice('Shibboleth for AuthMgrPlus requires plugin AuthMgrPlus to be installed and active', 'error');
        // Deactivate Shibboleth plugin
        yourls_update_option( 'active_plugins', array_diff( $activePlugins, ['shibboleth/plugin.php'] ) );
        return;
    }
}

// Hook our custom function into the 'is_valid_user' filter
yourls_add_filter( 'is_valid_user', 'shibboleth_is_valid_user' );
function shibboleth_is_valid_user($unfiltered_valid) {
    // Check for attributes set by mod_shib
    if ( ($uid = shibboleth_get_uid())
        && ($entitlement = shibboleth_get_entitlement())
        // Check if entitlement matches regex
        && preg_match(SHIBBOLETH_ENTITLEMENT_REGEX, $entitlement)
    ) {
        yourls_set_user($uid);
        return true;
    }
    return $unfiltered_valid;
}

/**
 * Populate $amp_role_assignment array with corresponding roles
 */
yourls_add_action('pre_login', 'shibboleth_initAssignment');
function shibboleth_initAssignment(){
    global $amp_role_assignment;
    global $shibboleth_rbac_role_assignment;

    if (($uid = shibboleth_get_uid())
        && ($entitlement = shibboleth_get_entitlement())
        // Check if entitlement matches regex
        && preg_match(SHIBBOLETH_ENTITLEMENT_REGEX, $entitlement)
    ) {
        // Parse Regex to define AMP Role assignment
        foreach ($shibboleth_rbac_role_assignment as $role => $regex) {
            if (preg_match($regex, $entitlement)) {
                $amp_role_assignment[$role][] = $uid;
            }
        }
    }
}

/**
 * Redirect to shibboleth logout URL after logout
 */
yourls_add_action('logout', 'shibboleth_logout', 1000);
function shibboleth_logout()
{
    // Perform YOURLS logout
    yourls_store_cookie(null);
    // Redirect to Logout URL
    header("Location: " . SHIBBOLETH_LOGOUT_URL);
    exit;
}
