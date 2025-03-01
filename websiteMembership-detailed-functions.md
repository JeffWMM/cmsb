# 📌 Website Membership Plugin - Function Explanations

This document provides **function definitions with explanations** based on the extracted logic from `websiteMembership.php`.

---

## 📂 **Function Breakdown with Explanations**

### 🔹 `_websiteLogin_init()`

**🔍 Explanation:**
- **Function Name:** `_websiteLogin_init()`
- **Parameters:** ``
- **Purpose:** [Detailed function logic being examined]
- **Extracted Code Context:**
```php
if (defined('IS_CMS_ADMIN')) { return; } // only run this form website viewers, not CMS admin pages
  if (inCLI()) { return; } // don't run for command line scripts

  // load login functions
  require_once SCRIPT_DIR . "/lib/login_functions.php";
  if (@$GLOBALS['WSM_ACCOUNTS_TABLE']) { accountsTable($GLOBALS['WSM_ACCOUNTS_TABLE']); }
  if (@$GLOBALS['WSM_SEPARATE_LOGIN']) { cookiePrefix('web'); } // use different prefix for login cookies

  // create accounts table if needed
  wsm_customAcc
```
---

### 🔹 `websiteLogin_redirectToLogin($returnAfterLogin = true)`

**🔍 Explanation:**
- **Function Name:** `websiteLogin_redirectToLogin()`
- **Parameters:** `$returnAfterLogin = true`
- **Purpose:** [Detailed function logic being examined]
- **Extracted Code Context:**
```php
// remember page they're trying to access
  if ($returnAfterLogin) { setPrefixedCookie('lastUrl', thisPageUrl()); }

  // redirect to login
  $loginUrl = $GLOBALS['WEBSITE_LOGIN_LOGIN_FORM_URL'] . "?loginRequired=1";
  redirectBrowserToURL($loginUrl);
  exit;
}


// be sure to set password or user will be logged out.  The $password argument isn't required by the function for legacy support
function websiteLogin_setLoginTo($username, $password = null) {
  loginCookie_set($username, getPasswor
```
---

### 🔹 `_websiteLogin_getCurrentUser()`

**🔍 Explanation:**
- **Function Name:** `_websiteLogin_getCurrentUser()`
- **Parameters:** ``
- **Purpose:** [Detailed function logic being examined]
- **Extracted Code Context:**
```php
global $CURRENT_USER;

  // load current user
  $CURRENT_USER = getCurrentUser();
  if (!$CURRENT_USER) { return false; }

  // error checking - logoff expired and disabled users
  if (@$CURRENT_USER['disabled'])    { alert(t("Your account has been disabled.")); }
//if (@$CURRENT_USER['isExpired'])   { alert(t("Your account has expired.")); } // future: maybe we should add an expires url where user gets redirect when their account has expired? For subscription renewal
  if (alert()) {
    log
```
---

### 🔹 `_websiteLogin_login()`

**🔍 Explanation:**
- **Function Name:** `_websiteLogin_login()`
- **Parameters:** ``
- **Purpose:** [Detailed function logic being examined]
- **Extracted Code Context:**
```php
global $CURRENT_USER;

  // attempt login?
  if (@$_REQUEST['username'] && @$_REQUEST['password']) {
    foreach (array('username','password') as $field) { // v1.10 remove leading and trailing whitespace
      $_REQUEST[$field] = preg_replace("/^\s+|\s+$/s", '', @$_REQUEST[$field]);
    }

    // get a list of accounts matching password and either email or username (we allow login with either)
    // ... checking for valid password ensure we get error messages from getCurrentUser() that are f
```
---

### 🔹 `_websiteLogin_logoff()`

**🔍 Explanation:**
- **Function Name:** `_websiteLogin_logoff()`
- **Parameters:** ``
- **Purpose:** [Detailed function logic being examined]
- **Extracted Code Context:**
```php
// get logoff url
  $currentPageUrl = (@$_REQUEST['action'] == 'logoff') ? thisPageUrl(array('action' => null)) : thisPageUrl(); // remove action=logoff to prevent redirect loops
  $logoffUrl = coalesce(@$_SERVER['HTTP_REFERER'], $GLOBALS['WEBSITE_LOGIN_POST_LOGOFF_URL'],  $currentPageUrl, '/');

  // logoff and redirect
  user_logoff($logoffUrl);
  exit;
}

//
function websiteLogin_pluginDir() {
  return __DIR__;
}


//
function wsm_generatePassword() {
  $password = substr(md5(uniqid(mt_ra
```
---

### 🔹 `wsm_sendSignupEmail($userNum, $passwordText)`

**🔍 Explanation:**
- **Function Name:** `wsm_sendSignupEmail()`
- **Parameters:** `$userNum, $passwordText`
- **Purpose:** [Detailed function logic being examined]
- **Extracted Code Context:**
```php
$user         = mysql_get(accountsTable(), $userNum);

  $placeholders = array_keys_prefix('user.', $user);
  $placeholders['user.password'] = $passwordText;
  $placeholders['loginUrl']      = realUrl($GLOBALS['WEBSITE_LOGIN_LOGIN_FORM_URL']);
  unset( $placeholders['user._tableName'] ); 

  $emailHeaders = emailTemplate_loadFromDB(array(
    'template_id'  => 'USER-SIGNUP',
    'placeholders' => $placeholders,
  ));
  $mailErrors   = sendMessage($emailHeaders);

  //
  return array($mailErro
```
---

### 🔹 `wsm_customAccountsTable_hashPasswords($tableName, $isNewRecord, $oldRecord)`

**🔍 Explanation:**
- **Function Name:** `wsm_customAccountsTable_hashPasswords()`
- **Parameters:** `$tableName, $isNewRecord, $oldRecord`
- **Purpose:** [Detailed function logic being examined]
- **Extracted Code Context:**
```php
global $SETTINGS;

  // skip for all but custom-accounts tables
  if (!$GLOBALS['WSM_ACCOUNTS_TABLE'])              { return; } // skip if no custom accounts table set
  if ($GLOBALS['WSM_ACCOUNTS_TABLE'] == 'accounts') { return; } // skip if using default 'accounts' table
  if ($GLOBALS['WSM_ACCOUNTS_TABLE'] != $tableName) { return; } // skip if the table being saved isn't the custom-accounts table

  // encrypt password being submitted in form input
  $_REQUEST['password'] = getPasswordDige
```
---

### 🔹 `wsm_customAccountsTable_create()`

**🔍 Explanation:**
- **Function Name:** `wsm_customAccountsTable_create()`
- **Parameters:** ``
- **Purpose:** [Detailed function logic being examined]
- **Extracted Code Context:**
```php
// check for custom accounts table
  if (accountsTable() == 'accounts') { return; }

  // check if schema exists
  $schemaPath = realpath(DATA_DIR . '/schema') . "/" .accountsTable(). ".ini.php";
  if (file_exists($schemaPath)) { return; }

  // create schema
  $schema = array(
    '_detailPage' => '',
    '_disableAdd' => '0',
    '_disableErase' => '0',
    '_disableModify' => '0',
    '_disablePreview' => '0',
    '_disableView' => '1',
    '_filenameFields' => '',
    '_hideRecordsFromDis
```
---

### 🔹 `wsm_plugin_menu_redirect_templates()`

**🔍 Explanation:**
- **Function Name:** `wsm_plugin_menu_redirect_templates()`
- **Parameters:** ``
- **Purpose:** [Detailed function logic being examined]
- **Extracted Code Context:**
```php
redirectBrowserToURL('?menu=_email_templates');
}

//
function wsm_plugin_menu_redirect_generator() {
  redirectBrowserToURL('?menu=_codeGenerator&_generator=wsm_codeGenerator');
}

//
function wsm_codeGenerator() {
  require_once("wsm_codeGenerator.php"); wsm_codeGenerator_showPage();
  exit;
}

//
function wsm_emailTemplates_install() {
  ### NOTE: Make sure this file (admin_functions.php) is saved as UTF-8 or chars with accents may not get saved to MySQL on insert


  // USER-PASSWORD-RESE
```
---
