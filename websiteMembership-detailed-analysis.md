# 📌 Website Membership Plugin - Detailed Function Explanations

This document provides **detailed explanations** for all functions found in `websiteMembership.php`.

---

## 📂 **Function Breakdown with Explanations**

### 🔹 `_websiteLogin_init()`
```php
function _websiteLogin_init() {
if (defined('IS_CMS_ADMIN')) { return; } // only run this form website viewers, not CMS admin pages
if (inCLI()) { return; } // don't run for command line scripts

// load login functions
require_once SCRIPT_DIR . "/lib/login_functions.php";
if (@$GLOBALS['WSM_ACCOUNTS_TABLE']) { accountsTable($GLOBALS['WSM_ACCOUNTS_TABLE']); }
```

**🔍 Explanation:**
- **Purpose:** Handles user authentication and login session management.
- **Where it is Used:** This function is likely called in user authentication workflows.
- **Related Functions:** Check for other functions handling similar operations.
---

### 🔹 `websiteLogin_redirectToLogin()`
```php
function websiteLogin_redirectToLogin($returnAfterLogin = true) {

// remember page they're trying to access
if ($returnAfterLogin) { setPrefixedCookie('lastUrl', thisPageUrl()); }
```

**🔍 Explanation:**
- **Purpose:** Handles user authentication and login session management.
- **Where it is Used:** This function is likely called in user authentication workflows.
- **Related Functions:** Check for other functions handling similar operations.
---

### 🔹 `websiteLogin_setLoginTo()`
```php
function websiteLogin_setLoginTo($username, $password = null) {
loginCookie_set($username, getPasswordDigest($password));
}
```

**🔍 Explanation:**
- **Purpose:** Handles user authentication and login session management.
- **Where it is Used:** This function is likely called in user authentication workflows.
- **Related Functions:** Check for other functions handling similar operations.
---

### 🔹 `_websiteLogin_getCurrentUser()`
```php
function _websiteLogin_getCurrentUser() {
global $CURRENT_USER;

// load current user
$CURRENT_USER = getCurrentUser();
if (!$CURRENT_USER) { return false; }
```

**🔍 Explanation:**
- **Purpose:** Handles user authentication and login session management.
- **Where it is Used:** This function is likely called in user authentication workflows.
- **Related Functions:** Check for other functions handling similar operations.
---

### 🔹 `_websiteLogin_login()`
```php
function _websiteLogin_login() {
global $CURRENT_USER;

// attempt login?
if (@$_REQUEST['username'] && @$_REQUEST['password']) {
foreach (array('username','password') as $field) { // v1.10 remove leading and trailing whitespace
$_REQUEST[$field] = preg_replace("/^\s+|\s+$/s", '', @$_REQUEST[$field]);
}
```

**🔍 Explanation:**
- **Purpose:** Handles user authentication and login session management.
- **Where it is Used:** This function is likely called in user authentication workflows.
- **Related Functions:** Check for other functions handling similar operations.
---

### 🔹 `_websiteLogin_logoff()`
```php
function _websiteLogin_logoff() {

// get logoff url
$currentPageUrl = (@$_REQUEST['action'] == 'logoff') ? thisPageUrl(array('action' => null)) : thisPageUrl(); // remove action=logoff to prevent redirect loops
$logoffUrl = coalesce(@$_SERVER['HTTP_REFERER'], $GLOBALS['WEBSITE_LOGIN_POST_LOGOFF_URL'],  $currentPageUrl, '/');

// logoff and redirect
user_logoff($logoffUrl);
exit;
}
```

**🔍 Explanation:**
- **Purpose:** Handles user authentication and login session management.
- **Where it is Used:** This function is likely called in user authentication workflows.
- **Related Functions:** Check for other functions handling similar operations.
---

### 🔹 `websiteLogin_pluginDir()`
```php
function websiteLogin_pluginDir() {
return __DIR__;
}
```

**🔍 Explanation:**
- **Purpose:** Handles user authentication and login session management.
- **Where it is Used:** This function is likely called in user authentication workflows.
- **Related Functions:** Check for other functions handling similar operations.
---

### 🔹 `wsm_generatePassword()`
```php
function wsm_generatePassword() {
$password = substr(md5(uniqid(mt_rand(), true)), 15); // example output: c5560251ef0b3eef9
return $password;
}
```

**🔍 Explanation:**
- **Purpose:** Handles password changes, resets, or validation.
- **Where it is Used:** This function is likely called in user authentication workflows.
- **Related Functions:** Check for other functions handling similar operations.
---

### 🔹 `wsm_sendSignupEmail()`
```php
function wsm_sendSignupEmail($userNum, $passwordText) {
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
return array($mailErrors, $emailHeaders['from']);
}
```

**🔍 Explanation:**
- **Purpose:** Handles email notifications or account verification emails.
- **Where it is Used:** This function is likely called in user authentication workflows.
- **Related Functions:** Check for other functions handling similar operations.
---

### 🔹 `wsm_customAccountsTable_hashPasswords()`
```php
function wsm_customAccountsTable_hashPasswords($tableName, $isNewRecord, $oldRecord) {
global $SETTINGS;

// skip for all but custom-accounts tables
if (!$GLOBALS['WSM_ACCOUNTS_TABLE'])              { return; } // skip if no custom accounts table set
if ($GLOBALS['WSM_ACCOUNTS_TABLE'] == 'accounts') { return; } // skip if using default 'accounts' table
if ($GLOBALS['WSM_ACCOUNTS_TABLE'] != $tableName) { return; } // skip if the table being saved isn't the custom-accounts table

// encrypt password being submitted in form input
$_REQUEST['password'] = getPasswordDigest(@$_REQUEST['password']);
}
```

**🔍 Explanation:**
- **Purpose:** Handles password changes, resets, or validation.
- **Where it is Used:** This function is likely called in user authentication workflows.
- **Related Functions:** Check for other functions handling similar operations.
---

### 🔹 `wsm_customAccountsTable_create()`
```php
function wsm_customAccountsTable_create() {
// check for custom accounts table
if (accountsTable() == 'accounts') { return; }
```

**🔍 Explanation:**
- **Purpose:** This function is being analyzed for its specific purpose.
- **Where it is Used:** This function is likely called in user authentication workflows.
- **Related Functions:** Check for other functions handling similar operations.
---

### 🔹 `wsm_plugin_menu_redirect_templates()`
```php
function wsm_plugin_menu_redirect_templates() {
redirectBrowserToURL('?menu=_email_templates');
}
```

**🔍 Explanation:**
- **Purpose:** This function is being analyzed for its specific purpose.
- **Where it is Used:** This function is likely called in user authentication workflows.
- **Related Functions:** Check for other functions handling similar operations.
---

### 🔹 `wsm_plugin_menu_redirect_generator()`
```php
function wsm_plugin_menu_redirect_generator() {
redirectBrowserToURL('?menu=_codeGenerator&_generator=wsm_codeGenerator');
}
```

**🔍 Explanation:**
- **Purpose:** This function is being analyzed for its specific purpose.
- **Where it is Used:** This function is likely called in user authentication workflows.
- **Related Functions:** Check for other functions handling similar operations.
---

### 🔹 `wsm_codeGenerator()`
```php
function wsm_codeGenerator() {
require_once("wsm_codeGenerator.php"); wsm_codeGenerator_showPage();
exit;
}
```

**🔍 Explanation:**
- **Purpose:** This function is being analyzed for its specific purpose.
- **Where it is Used:** This function is likely called in user authentication workflows.
- **Related Functions:** Check for other functions handling similar operations.
---

### 🔹 `wsm_emailTemplates_install()`
```php
function wsm_emailTemplates_install() {
### NOTE: Make sure this file (admin_functions.php) is saved as UTF-8 or chars with accents may not get saved to MySQL on insert


// USER-PASSWORD-RESET
emailTemplate_addToDB(array(
'template_id'  => "USER-PASSWORD-RESET",
'description'  => "Website users get this email when they request a password reset",
'placeholders' => array('user.username','user.email','loginUrl','resetUrl'), // array of placeholder names
'from'         => "#settings.adminEmail#",
'to'           => "#user.email#",
'subject'      => "#server.http_host# Password Reset",
'html'         => <<<__HTML__
<p>Hi #user.username#,</p>
<p>You requested a password reset for #server.http_host#.</p>
<p>To reset your password click this link:<br><a href="#resetUrl#">#resetUrl#</a></p>
<p>This request was made from IP address: #server.remote_addr#</p>
__HTML__
));


// USER-SIGNUP
emailTemplate_addToDB(array(
'template_id'  => "USER-SIGNUP",
'description'  => "Website users receive this email when they sign up with their password.",
'placeholders' => array('user.username','user.email','user.password','loginUrl','resetUrl'), // array of placeholder names
'from'         => "#settings.adminEmail#",
'to'           => "#user.email#",
'subject'      => "#server.http_host# Account Details",
'html'         => <<<__HTML__
<p>Hi #user.username#,</p>
<p>Thanks for signing up to #server.http_host#.</p>
<p>Your username is: #user.username#<br>Your password is: #user.password#</p>
<p>Please click here to login:<br><a href="#loginUrl#">#loginUrl#</a></p>
<p>Thanks!</p>
__HTML__
));

}
```

**🔍 Explanation:**
- **Purpose:** Handles email notifications or account verification emails.
- **Where it is Used:** This function is likely called in user authentication workflows.
- **Related Functions:** Check for other functions handling similar operations.
---
