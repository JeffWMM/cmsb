# 📌 Detailed cmsBuilder Function Breakdown

This document provides an **in-depth breakdown** of all **functions** found in the core **cmsBuilder** files.

---

## **📂 Function Index by File**
Below is a detailed list of **every function** found in the cmsBuilder system.


### 📄 cmsb/cron.php
- `cron_dispatcher()`
- `cron_dispatcher_process(array $cron, int $cronLastRunTime, int $thisCronRunTime)`
- `if($cronExprParseErrors)`
- `if(!inCLI()`
- `cron_logErrorsOnDieOrExit()`
- `cronExpression_getLastScheduledTime(string $cronExpression, int $oldestTimeToCheck = 0, ?string &$parseErrors = '')`
- `cronExpression_getValidValuesForField(string $type, string $expr)`
---

### 📄 cmsb/api.php
- `getRoute()`
- `route404NotFound()`
- `getGoogleOauthProvider()`
- `oauthGoogleRedirect()`
- `oauthGoogleCallback()`
- `verifyGoogleIdToken($idToken, $googleClientId)`
---

### 📄 cmsb/plugins/developerConsole.php
- `developerConsole_checkSecurity()`
- `_developerConsole_showForm_javascript($mode='')`
- `developerConsole_mysql_selectTable()`
- `developerConsole_mysql_selectField()`
- `developerConsole_selectPreset()`
- `developerConsole_executeQuery()`
- `flipResultsTable()`
- `mysqlConsole()`
- `developerConsole_mysql_showForm()`
- `developerConsole_mysql_doQuery()`
- `whitespace_char($showLetter, $titleText)`
- `whitespace_null()`
- `developerConsole_mysql_listFieldOptions()`
- `developerConsole_shell_showForm()`
- `_developerConsole_shell_showForm_javascript()`
- `shellConsole_selectPreset()`
- `shellConsole_executeCommand()`
- `developerConsole_shell_doQuery()`
- `developerConsole_php_showForm()`
- `developerConsole_php_doQuery()`
---

### 📄 cmsb/plugins/_example_plugin.php
- `samplePlugin_short_page_example()`
- `samplePlugin_long_page_example()`
- `_my_content_returned_example($arg1 = "test")`
- `_my_content_printed_example($arg1 = "test")`
---

### 📄 cmsb/plugins/_example_cron.php
- `cron_example()`
---

### 📄 cmsb/plugins/offlineMode/offlineMode.php
- `offlineMode_includeCDN(string $html)`
- `offlineMode_getUrlFromTag(string $html)`
- `offlineMode_getLocalPathFromUrl(string $url)`
- `offlineMode_getTagForLocalFile(string $relUrl)`
- `offlineMode_updateOfflineResources()`
- `offlineMode_cacheMissingFiles(string $relPath, string $url)`
- `offlineMode_cacheCSSLinkedResources($relPath, $url, $html)`
- `offlineMode_getUrl(string $url)`
- `offlineMode_saveFile(string $relPath, string $html)`
- `offlineMode_downloadTinyMce(string $url)`
---

### 📄 cmsb/lib/schema_functions.php
- `createMissingSchemaTablesAndFields($schemaTables = null)`
- `createSchemaFromFile($sourcePath)`
- `getSortedSchemas()`
- `getSchemaTables(string $dir = '')`
- `loadSchema(string $tableName, ?string $schemaDir = '', bool $useCache = false)`
- `saveSchema($tableName, $schema, $schemaDir = '', $removePrefix = true)`
- `__sortSchemaFieldsByOrder($fieldA, $fieldB)`
- `getListOptionsFromSchema(array $fieldSchema, $record=null, $useCache=false, $listValues=null)`
- `getListOptionsFromSchema_maxResults()`
- `getSelectOptionsFromSchema($selectedValue, $fieldSchema, $showEmptyOptionFirst = false)`
- `schemaExists($tableName, $customSchemaDir = '')`
- `schema_isMultiValueField($tablename, $field)`
- `schema_addMissingMySqlColumns(string $fullTable, ?array $mysqlColumns = null)`
- `explodeTSV(string|int|float|null $valueOrTSV)`
- `implodeTSV(array $values)`
- `inTSV(string|int|float $haystack, string|int|float $needle)`
---

### 📄 cmsb/lib/wysiwyg.php
- `initWysiwyg($fieldname, $uploadBrowserCallback)`
---

### 📄 cmsb/lib/media_functions.php
- `media_showUploadifyLink($tableName, $fieldName, $recordNum)`
- `media_showFromMediaLibraryText($mediaNum)`
- `media_showRecordsUsingMedia()`
- `media_getUploadsUsingMedia($mediaNum)`
- `media_getAllMediaRecords($perPage, $pageNum = 1)`
- `media_replaceUploadsWithMedia($uploads)`
- `media_showMediaList($action)`
- `media_showMediaList_pagingButtons($action, $uploadsPerPage, $records)`
- `media_showMediaPreview($row, $maxWidth = 150, $maxHeight = 125)`
- `media_addMediaAjax()`
---

### 📄 cmsb/lib/errorlog_functions.php
- `logErrorsToDatabase()`
- `_enable_errorlog_textfile()`
- `errorlog_inCallerStack()`
- `errorlog_enable()`
- `_errorlog_catchRuntimeErrors($errno = '', $errstr = '', $errfile = '', $errline = '')`
- `_errorlog_catchFatalErrors()`
- `_errorlog_catchUncaughtExceptions($e, $allowResume = false)`
- `_errorlog_alreadySeenError($filePath, $lineNum)`
- `_errorlog_logErrorRecord(array $logData)`
- `_errorlog_errnoToConstantName($errno)`
- `_errorlog_errnoToConstantLabel($errno)`
- `_errorlog_sendEmailAlert()`
- `_errorlog_getUserErrorMessage($recordNum = null, $errstr = null, $errfile = null, $errline = null)`
- `_errorlog_getCallStackText(?Throwable $e = null, $errno = null, $errstr = null, $errfile = null, $errline = null)`
- `_errorlog_getCallStackArray(?Throwable $e = null, $errno = null, $errstr = null, $errfile = null, $errline = null)`
- `_errorlog_getBrokenPhpFunctionsWarning()`
- `_errorlog_serialize($input)`
- `getExternalCaller(?string $errfile, ?int $errline, ?Throwable $e = null)`
- `errorlog_lastError(?string $message = null, ?int $type = null)`
- `errorlog_clearLast()`
- `error_get_last_message()`
- `errorDB_getIsolatedConnection()`
- `errorDB_addErrorRecord($colsToValues)`
- `errorDB_removeOldRecords()`
- `errorDB_getLatestErrors(int $max = 25)`
---

### 📄 cmsb/lib/init.php
- `init()`
- `checkServerRequirements()`
- `setupAutoLoaderAndHelpers()`
- `loadClassAliases()`
- `configurePhpSettings()`
- `defineLegacyGlobals()`
- `registerSessionHandler()`
- `startSession()`
---

### 📄 cmsb/lib/upgrade_functions.php
- `showUpgradeErrors()`
- `_upgradeToVersion3_75()`
- `_upgradeToVersion3_72()`
- `_upgradeToVersion3_71()`
- `_upgradeToVersion3_70()`
- `_upgradeToVersion3_65()`
- `_upgradeToVersion3_59()`
- `_upgradeToVersion3_52()`
- `_upgradeToVersion3_14()`
- `_upgradeToVersion3_11()`
- `_upgradeToVersion3_00()`
- `_upgradeToVersion2_09()`
- `_upgradeToVersion2_07()`
- `_upgradeToVersion2_05()`
- `_upgradeToVersion1_24()`
- `_upgradeToVersion1_10()`
- `_upgradeToVersion1_10_accessLevels()`
- `_upgradeToVersion1_08()`
- `_upgradeToVersion1_07()`
- `_upgradeToVersion1_06()`
- `_upgradeToVersion1_04()`
- `saveAndRefresh($version, $build = null)`
- `_upgradeAccounts()`
- `_removeOldCacheFiles()`
- `_notifyUpgradeComplete()`
- `_upgrade_removeColumnIfExists(string $tableName, string $fieldname)`
- `_getTinymce4UpgradeErrors($customWysiwygCode)`
- `forceValidCssTheme($defaultThemeFile = 'theme_blue.css')`
---

### 📄 cmsb/lib/pluginUI_functions.php
- `addGenerator($functionName = '', $name = '', $description = '', $builtInType = 'private')`
- `getGenerators($type)`
- `plugin_header($title, $buttons = '', $showBackToPluginsButton = true)`
- `plugin_footer()`
---

### 📄 cmsb/lib/image_functions.php
- `saveResampledImageAs($targetPath, $sourcePath, $maxWidth, $maxHeight, $crop = false)`
- `_fastimagecopyresampled(&$dst_image, $src_image, $dst_x, $dst_y, $src_x, $src_y, $dst_w, $dst_h, $src_w, $src_h, $imageType, $quality = 3)`
- `_image_saveTransparency(&$targetImage, &$sourceImage, $imageType)`
- `_image_fixJpegExifOrientation($imageFilePath)`
- `isImage($filePathOrFileExtension, $testAsExt = false)`
- `isImage_SVG($filePath)`
- `image_convertCMYKToRGBIfNeeded($filePath)`
- `image_resizeCalc($sourceWidth, $sourceHeight, $targetWidthMax, $targetHeightMax, $allowScaleUp = false)`
- `image_convertToWebp($sourceFile, $targetFile = '', $extension = 'imagick')`
- `image_isAnimatedGif($sourceFile)`
---

### 📄 cmsb/lib/Server.php
- `inCLI()`
- `isMac()`
- `isUnix()`
- `isWindows()`
- `isDevServer()`
- `isHTTPS()`
- `isTextOutput()`
- `isAjaxRequest()`
- `getWebRoot()`
- `getDataDir()`
- `getPhpBinaryPath($escapeShellCmd = true)`
- `forwardSlashes(string|null|false $path)`
- `_getServerTestData(?string $keysToInclude = null, ?string $valuesToMatch = null, ?string $valuesToExclude = null, ?string $keysToExclude = null)`
---

### 📄 cmsb/lib/old_alias_functions.php
- `_logUseOfOldFunction()`
- `_getCallerFileAndLine($depth = 1)`
- `countRecords($tableName, $whereClause = '')`
- `mysql_select_count_from($tableName, $whereClause = '')`
- `countRecordsByUser($tableName, $userNum = null)`
- `escapeMysqlString($string)`
- `xmp_r($string)`
- `getNumberFromEndOfUrl()`
- `mysql_query_fetch_row_assoc($query)`
- `mysql_query_fetch_row_array($query)`
- `mysql_query_fetch_all_assoc($query)`
- `mysql_query_fetch_all_array($query)`
- `escapeJs($str)`
- `loadINI($filepath)`
- `saveINI($filepath, $array, $sortKeys = 0)`
- `_encodeIniValues($array)`
- `_decodeIniValues($array)`
- `_decodeIniValues_replacement_callback($matches)`
- `userHasSectionEditorAccess($tableName)`
- `userHasSectionAuthorViewerAccess($tableName)`
- `userHasSectionAuthorAccess($tableName)`
- `userHasSectionViewerAccess($tableName)`
- `userHasSectionViewerAccessOnly($tableName)`
- `userHasSectionAuthorViewerAccessOnly($tableName)`
- `mysql_getValuesAsCSV($valuesArray, $defaultValue='0')`
- `_mysql_getMysqlSetValues($colsToValues)`
- `user_createLoginSession($username, $password = null)`
- `user_eraseLoginSession()`
- `user_loadWithSession()`
- `getCurrentUserAndLogin($useAdminUI = true)`
- `emailTemplate_load($options)`
- `emailTemplate_showPreviewHeader()`
- `getAdjustedLocalTime()`
- `escapeMysqlWildcards($string)`
- `getMysqlLimit($perPage, $pageNum)`
- `getAbsolutePath($relativePath, $baseDir = '.')`
- `isAbsolutePath($path)`
- `showHeader()`
- `showFooter()`
- `mysql_getMysqlSetValues($colsToValues)`
- `relatedRecordsButton($args = null)`
- `getListValues($tableName, $fieldName, $fieldValue)`
- `rename_winsafe($oldfile, $newfile)`
- `poweredByHTML()`
- `getFirstDefinedValue()`
- `coalesce()`
- `fixSlashes($path)`
- `getPhpExecutablePath()`
- `nullIfFalse($var)`
- `isAjaxRequest()`
- `startsWith($needle, $haystack, $caseSensitive = true)`
- `endsWith($needle, $haystack, $caseSensitive = true)`
- `contains($needle, $haystack, $caseSensitive = true)`
- `saveSettings($forceDevFile = false)`
- `loadStruct(string $filepath)`
- `saveStruct($filepath, $struct, $sortKeys = false, $headerMessage = '')`
- `loadStructOrINI($filepath)`
- `isInstalled($markAsInstalled = false)`
- `isUpgradePending()`
- `getValidationErrors($label, $value, $rulesString)`
- `_dieAsCaller_onUnsupportedBooleanNot($ruleName, $booleanNot, $rulesString)`
- `getOptionListErrors($options, $requiredOptions, $optionalOptions = [])`
- `dieAsCaller($message, $depth = 1)`
- `getPasswordDigest($passwordText, $forceEncode = false)`
- `_getExistingPasswordHash(string $emailOrUsername, $passwordText)`
- `isPasswordDigest($password)`
- `getNewPasswordErrors($passwordText, $passwordText2 = null, $username = '')`
- `user_logoff($redirectUrl = '')`
- `loginCookie_set($username, $passwordHash)`
- `loginCookie_get()`
- `loginCookie_remove()`
- `loginCookie_name($addCookiePrefix = false)`
- `getCurrentUser(&$loginExpired = false)`
- `getCurrentUserFromCMS()`
- `accountsTable($setValue = '')`
- `_init_loadSettings()`
- `listValues_pack($valuesArray)`
- `listValues_unpack($valuesAsTSV)`
---

### 📄 cmsb/lib/Settings.php
- `get(string $key)`
- `set(string $key, string|int $value)`
- `remove(string $key)`
- `update(array $keysToValues)`
- `loadArray(bool $useCache = true)`
- `saveArray(array $settings, bool $forceDevFile = false)`
- `getCurrentFile()`
- `getCurrentPath()`
- `getDevFile()`
- `getDevPath()`
- `usingDevFile()`
- `devServerErrorChecking()`
- `addMissingSettings(array $settings)`
- `updateDynamicSettings(array $settings)`
- `getSettingDefaults()`
- `customSorting(array $settings)`
---

### 📄 cmsb/lib/plugin_functions.php
- `loadPlugins()`
- `getPluginList()`
- `_getPhpFilepathsFromPluginsDir()`
- `_getPluginData($filepath, $pathFromPluginsDir)`
- `isPluginActive($filename)`
- `plugin_getDeprecatedHooks()`
- `addAction($hookName, $function, $priority = 10, $acceptedArgs = null)`
- `addFilter($hookName, $function, $priority = 10, $acceptedArgs = null)`
- `doAction($hookName, $arg = '')`
- `applyFilters($hookName, $filteredValue = '')`
- `addCronJob($functionName, $activityName, $cronExpression)`
- `activatePlugin($file)`
- `deactivatePlugin($file)`
- `getPluginPathAndUrl($alternateFilename = '', $returnAbsoluteFilePath = false)`
- `plugin_createSchemas($tableNames = [])`
- `pluginAction_addHandlerAndLink($linkName, $functionName, $requiredAccess = 'admins')`
- `_pluginAction_addHandlerAndLink($pluginPath)`
- `pluginAction_addHandler($functionName, $requiredAccess = 'admins')`
- `_pluginAction_runHandler()`
- `pluginAction_getLink($functionName)`
- `pluginAction_addLink($labelOrHTML, $url = '')`
- `_pluginAction_addLink($pluginPath)`
- `pluginsCalled(string $name = '', ?string $type = null)`
- `_getIncludedMenuFiles($pluginPaths)`
---

### 📄 cmsb/lib/login_functions.php
- `loginExpirySeconds()`
- `encryptAllPasswords()`
---

### 📄 cmsb/lib/serverInfo_functions.php
- `updateServerChangeLog($forceUpdate = false)`
- `serverInfo_contentDeliveryNetwork()`
- `serverInfo_operatingSystem()`
- `serverInfo_serverName()`
- `serverInfo_serverAddr()`
- `serverInfo_webServer()`
- `serverInfo_webServer_controlPanel()`
- `serverInfo_databaseServer()`
- `serverInfo_databaseConnection()`
- `serverInfo_phpUser()`
---

### 📄 cmsb/lib/html_functions.php
- `checkedIf($fieldValue, $testValue, $returnValue = 0)`
- `selectedIf($fieldValue, $testValue, $returnValue = 0)`
- `getSelectOptions($selectedValue, $values, $labels = '', $showEmptyOptionFirst = false, $htmlEncodeInput = true)`
- `getSelectOptionsFromTable($tableName, $valueField, $labelField, $selectedValue, $showEmptyOptionFirst)`
- `jsEncode($str)`
- `js_escapef()`
- `htmlencode(string|int|float|null $input, bool $encodeBr = false, bool $double_encode = true)`
- `htmlencodef()`
- `urlencodeSpaces($value)`
- `htmlPurify($html, $config = [])`
- `tag($tagName, $attrs = [], $content = null, $skipEmptyAttr = true)`
- `attr($attrs = [], $skipEmptyAttr = true)`
---

### 📄 cmsb/lib/auditlog_functions.php
- `auditLog_addEntry($event, $additionalData = [], string $source = '')`
---

### 📄 cmsb/lib/database_functions.php
- `mysqli(?mysqli $setValue = null)`
- `connectIfNeeded()`
- `connectToMySQL($returnErrors = false)`
- `getIndexNameAndColumnListForField($fieldName, $columnType)`
- `_sortMenusByOrder(array $fieldA, array $fieldB)`
- `getTableNameWithoutPrefix($tableName)`
- `getTableNameWithPrefix($tableName)`
- `getMysqlTablesWithPrefix()`
- `getMySqlColsAndType($escapedTableName)`
- `getMysqlColumnType($tableName, $fieldname)`
- `getTablenameErrors($tablename)`
- `getListOptions($tablename, $fieldname, $useCache = false)`
- `getWhereForKeywords($keywordString, $fieldnames, $wantArray = false)`
- `backupDatabase($filenameOrPath = '', $selectedTable = '')`
- `backupDatabase_skippedTables()`
- `getBackupFiles_asArray()`
- `getBackupFiles_asOptions($defaultValue = '')`
- `restoreDatabase($filepath, $tablename = '')`
- `incrementalRestore($backupFilepath = '', $installFromBackup = false)`
- `_incrementalRestore_getMoreSqlStatements($filePath, $fileOffset)`
- `_incrementalDbAction_currentOperation($action = '', $actionValue = '')`
- `_incrementalDbAction_showInProgressError_HTTP503($showResumeLink = false)`
- `_incrementalDbAction_getProgress()`
- `restore_insertTablePrefix(string $sql)`
- `getDatabaseBackupDir()`
---

### 📄 cmsb/lib/User.php
- `setAccountsTable(string $table, bool $separateLogin = false)`
- `getAccountsTable()`
- `loginAs(?string $emailOrUsername, ?string $plaintextPassword)`
- `getLoginUserRecord(string $emailOrUsername, string $password)`
- `updatePasswordHash(string $plaintextPassword, array $user)`
- `isExpired(?array $user)`
- `isDisabled(?array $user)`
- `isLoggedIn()`
- `getCurrentUser(bool $useCache = true)`
- `getCurrentUserFromCMS($useCache = true)`
- `addAccessListField(array $user, string $accountsTable)`
- `setLegacyGlobal()`
- `updateLastLoginDate(?array $user)`
- `updateSessionPasswordChecksum()`
- `logout()`
- `logoutAndRedirect(?string $redirectUrl = null)`
- `getSessionKey()`
- `getSessionData()`
- `setSessionData(array $user)`
- `clearSessionData()`
- `showLoginForm(?array $errors = null)`
- `submitLoginForm(?string $username, ?string $password, ?string $redirectUrl)`
---

### 📄 cmsb/lib/security_functions.php
- `security_dieUnlessPostForm()`
- `security_dieUnlessInternalReferer($forceCheck = false)`
- `security_dieOnInvalidCsrfToken()`
- `security_disableExternalReferers()`
- `security_disablePostWithoutInternalReferer()`
- `security_warnOnInputWithNoReferer()`
- `security_getHiddenCsrfTokenField()`
- `_security_getProgramBaseRefererUrl()`
- `_security_clearAllUserInput()`
- `_security_isAllowedGetUrl()`
---

### 📄 cmsb/lib/upload_storage_strategy.php
- `upload_storage_strategy($newInstance = null)`
- `storeMainFile($mainUploadWorkingPath, $desiredFilename, $fieldSchema, &$uploadRecordDetails)`
- `storeThumbFile($thumbWorkingPath, $fieldSchema, $suffix, &$uploadRecordDetails)`
- `makeUploadPathAndUrlAbsolute(&$record, $fieldSchema)`
- `removeUploadsForRecord($record)`
- `resizeThumb($uploadRecord, $thumbNum, $maxWidth, $maxHeight)`
- `storeMainFile($mainUploadWorkingPath, $desiredFilename, $fieldSchema, &$uploadRecordDetails)`
- `storeThumbFile($thumbWorkingPath, $fieldSchema, $suffix, &$uploadRecordDetails)`
- `makeUploadPathAndUrlAbsolute(&$record, $fieldSchema)`
- `removeUploadsForRecord($record)`
- `resizeThumb($uploadRecord, $thumbNum, $maxWidth, $maxHeight, $crop = false)`
---

### 📄 cmsb/lib/file_functions.php
- `absPath(string $inputPath, string $baseDir = '.')`
- `isAbsPath(string $path)`
- `mkdir_recursive($dir, $mode = null)`
- `file_put_contents_atomic($filepath, $content)`
- `isPathWritable($path)`
- `makeWritable($filepath)`
- `scandir_recursive($dir, $regexp = '', $depth = 99)`
- `unlink_on_shutdown($filepath)`
- `uber_file_get_contents(string $filepath)`
---

### 📄 cmsb/lib/forgotPassword_functions.php
- `forgotPassword()`
- `resetPassword()`
- `_isValidPasswordResetCode($userNum, $resetCode)`
- `_generatePasswordResetCode($userNum, $dayModifier = 0)`
---

### 📄 cmsb/lib/mail_functions.php
- `sendMessage(array $options = [])`
- `sendBackground($options = [])`
- `getMessageErrors(array $options)`
- `logMessage(array $options, bool $backgroundSend = false)`
- `_sendMessage_phpMailer($options)`
- `_sendMessage_phpMailer_init($options, $mailSettings)`
- `_sendMessage_setEmailAddresses(PHPMailer $mail, array $options)`
- `_sendMessage_setEmailContent(PHPMailer $mail, array $options)`
- `_sendMessage_useSMTP(PHPMailer $mail, array $options, string $method)`
- `_sendMessage_useGoogleOAuth(PHPMailer $mail, array $options, array $mailSettings)`
- `_sendMessage_useMicrosoftOAuth(PHPMailer $mail, array $options, array $mailSettings)`
- `emailTemplate_loadFromDB($options)`
- `emailTemplate_replacePlaceholders($emailHeaders, $customPlaceholders)`
- `emailTemplate_addToDB($record)`
- `emailTemplate_addDefaults()`
- `isValidEmail(mixed $input, bool $allowMultiple = false)`
---

### 📄 cmsb/lib/viewer_functions_old.php
- `getListRows($options)`
- `getRecord($options)`
- `getUploads($tableName, $fieldName, $recordNum)`
- `_getOptionErrors($requiredOptions, $validOptions, $options)`
---

### 📄 cmsb/lib/admin_functions.php
- `isIpAllowed(bool $forceCheck = false, string $allowedIPsAsCSV = '')`
- `installIfNeeded()`
- `installIfNeeded_preSaveErrorChecking()`
- `installIfNeeded_onSave()`
- `installIfNeeded_onSaveErrorChecking()`
- `installIfNeeded_createAdminUser()`
- `installIfNeeded_restoreFromBackup()`
- `upgradeIfNeeded()`
- `checkFilePermissions()`
- `allowSublicensing()`
- `showInterfaceError($alert)`
- `showInterface($body, $showHeaderAndFooter = "n/a")`
- `noCacheUrlForCmsFile($pathFromCmsDir)`
- `clearAlertsAndNotices()`
- `getBootstrapFieldWidthClass($sizeName = null)`
- `tableRows(string $startTag, callable|string $callback, string $endTag, SmartArray|SmartNull|bool $rowsRowOrBool)`
- `wysiwygIncludeDomainInLinks(?bool $setValue = null)`
- `userSectionAccess($tableName)`
- `userHasFieldAccess($fieldSchema)`
---

### 📄 cmsb/lib/Request.php
- `get(?string $key = null, bool $allowArray = false)`
- `post(?string $key = null, bool $allowArray = false)`
- `request(?string $key = null, bool $allowArray = false)`
- `normalizeKeys(array $input)`
- `fetchData(array $source, ?string $key, bool $allowArray)`
- `sanitize(string|array|int|float|bool|null $input)`
---

### 📄 cmsb/lib/Password.php
- `isValid(string $passwordText, string $passwordHash)`
- `createHash(string $plaintext)`
- `getNewPasswordErrors($passwordText, $passwordText2 = null, $username = '')`
- `needsRehash(string $hash)`
- `hashOptions()`
---

### 📄 cmsb/lib/adminUI_functions.php
- `adminUI($args)`
- `adminUI_header($args)`
- `adminUI_footer()`
- `_adminUI_validateAttrs($attrs, $requiredAttrs, $optionalAttrs)`
- `adminUI_button($attrs)`
- `adminUI_buttonLink($attrs)`
- `adminUI_checkbox($attrs)`
- `adminUI_hidden($attrs)`
- `adminUI_separator($attrs = [])`
- `adminUI_contentFollows($args)`
- `_adminUI_inputArraysToHTML($args)`
- `unbindAndOrSubmit()`
- `renderAdminView(array $args)`
- `renderView(string $absPath, ?array $viewVars = [])`
- `outputJsonResponse(Closure $actionHandler)`
- `adminUI_helpIcon($helpText = '')`
- `adminUI_warningIcon($helpText = '')`
---

### 📄 cmsb/lib/viewer_functions.php
- `getRecords($options)`
- `getRecordsCustom($options)`
- `_getRecords_preview($schemaIn, $options)`
- `_getRecords_errorChecking($options)`
- `_getRecords_getQuery($options, $schema)`
- `_getRecords_getCountQuery($options, $schema)`
- `_getRecords_loadResults($query, $countQuery, $options, $schema)`
- `__replaceUnderscoresInRequest($tablename)`
- `_getRecords_joinTable(&$rows, $options, $joinTable = '')`
- `_getRecords_addPseudoFields(&$records, $options, $schema)`
- `_getRecords_addUploadFields(&$rows, $options, $schema, $preSaveTempId = null)`
- `_getRecords_getListDetails($options, $rowCount, $totalRecords, $schema)`
- `_getOrderByFromUrl($schema)`
- `whereRecordNumberInUrl($altWhere = null)`
- `getCategories($options)`
- `_categoryMatchesFormatRules($category, $selectedCategory, $rootDepthVisible, $childDepthVisible, $parentVisibility)`
- `_getListItemStartTags($prevCategory, $thisCategory, $nextCategory, $options)`
- `_getListItemEndTags($prevCategory, $thisCategory, $nextCategory)`
- `_createDefaultWhereWithFormInput($schema, $where, $options)`
- `_getListDetails($options, $rowCount)`
- `searchMultipleTables($searchTables, $searchOptions)`
- `getLastNumberInUrl($defaultNum = null)`
- `_addWhereConditionsForSpecialFields($schema, $extraConditions, $options = [], $tableName = '')`
- `_getWhereForSearchQuery($query, $fieldnames, $schema = null)`
- `_getLink($detailUrl, $filenameFieldValue, $recordNum, $useSeoUrls)`
- `getFilenameFieldValue($record, $filenameFields)`
- `getPrevAndNextRecords($options)`
- `incrementCounterField($tablename, $fieldname, $recordNumber)`
- `getListLabels($tableName, $fieldName, $fieldValue)`
---

### 📄 cmsb/lib/http_functions.php
- `getPage($url, $connectTimeout = 5, $headers = [], $POST = false, $responseBody = '')`
- `_getPage_chunkedDecode($responseBody)`
- `curl_get($url, $queryParams = [], &$requestInfo = [], $curl_options = [])`
- `curl_post($url, $postFields = [], &$requestInfo = [], $curl_options = [])`
- `setPrefixedCookie($unprefixedName, $cookieValue, $cookieExpires = 0, $allowHttpAccessToHttpsCookies = false, $allowJavascriptAccess = false)`
- `removePrefixedCookie($unprefixedName)`
- `getPrefixedCookie($unprefixedName)`
- `cookiePrefix($setLeadingText = '', $returnArray = false)`
- `isAbsoluteUrl($url)`
- `realUrl($targetUrl, $baseUrl = null)`
- `redirectBrowserToURL($url, $queryStringsOnly = false)`
- `safe301Redirect($url)`
- `dieWith404($message = "Page not found!")`
- `thisPageUrl($newQueryValues = [], $queryStringOnly = false)`
---

### 📄 cmsb/lib/SessionHandler.php
- `register()`
- `getCookieName()`
- `getExpiresDateUTC()`
- `open(string $path, string $name)`
- `read(#[\SensitiveParameter] string $id)`
- `write(#[\SensitiveParameter] string $id, #[\SensitiveParameter] string $data)`
- `destroy(#[\SensitiveParameter] string $id)`
- `close()`
- `gc(int $max_lifetime)`
- `validateId(string $id)`
- `updateTimestamp(string $id, string $data)`
---

### 📄 cmsb/lib/shell_functions2.php
- `_shellCommand_shell_exec(string $command, ?int &$exitCode = null, ?string &$functionUsed = null)`
- `_shellCommand_popen(string $command, ?int &$exitCode = null, ?string &$functionUsed = null)`
- `_shellCommand_proc_open(string $command, ?int &$exitCode = null, ?string &$functionUsed = null)`
---

### 📄 cmsb/lib/CMS.php
- `init()`
- `isInstalled($markAsInstalled = false)`
- `isUpgradePending()`
- `showDebugFooter()`
---

### 📄 cmsb/lib/SmartArrayLoadHandler.php
- `load(SmartArray $smartArray, string $fieldName)`
- `getAccount(SmartArray $smartArray, string $fieldName)`
- `getListRecordsFromText(SmartArray $smartArray, string $fieldName, array $schema)`
- `getListRecordsFromTable(SmartArray $smartArray, string $sourceColumn, array $schema)`
- `getListRecordsFromQuery(SmartArray $smartArray, string $column, array $schema)`
- `getForeignKeyTargetRecords(SmartArray $smartArray, string $fkColumn, array $schema)`
- `getCachedRecords(string $baseTable, string $column, array $values, array $tsvValuesToCache)`
- `getCachedUploads(SmartArray $smartArray, string $fieldName, array $schema)`
---

### 📄 cmsb/lib/language_functions.php
- `t($str)`
- `et($str)`
- `eht($str)`
- `translateString($originalString)`
- `_languageFile_save($filepath, $translation)`
- `_languageFiles_addString($defaultLangDir, $targetLangDir, $originalString)`
- `_languageFiles_getDirs()`
---

### 📄 cmsb/lib/common.php
- `showExecuteSeconds(bool $return = false)`
- `getEvalOutput(?string $string, ?string &$evalErrors = null)`
- `showme($var, $fancy = false)`
- `renameOrRemoveDefaultFiles()`
- `alert(string $message = '')`
- `notice(string $message = '')`
- `warning(string $message = '')`
- `success(string $message = '')`
- `displayAlertsAndNotices()`
- `_formatNewNotification(string $message)`
- `_displayNotificationType($type, $message)`
- `isBeingRunDirectly()`
- `formatBytes(int|float|string|null $bytes, int $precision = 2)`
- `ob_disable(bool $forHTML = false)`
- `generateSomeHtml()`
- `ob_capture(callable $function, ...$args)`
- `_getRecordValuesFromFormInput(bool $usePreviewPrefix = false)`
- `_getHour24ValueFromDateInput($fieldname)`
- `_addUndefinedDefaultsToNewRecord($colsToValues, $mySqlColsAndTypes)`
- `extractSuffixChar($string, $acceptableSuffixChars)`
- `prettyDate($dateStringOrUnixTime)`
- `preg_match_get($pattern, $subject, &$matches = [], $flags = 0, $offset = 0)`
- `getRequestedAction($defaultAction = '')`
- `json_encode_pretty($struct)`
- `utf8_force($stringOrArray, $replace4ByteUTF8 = false, $convertFromEncoding = '')`
- `includeCDN($html)`
- `stri_ends_with(string $haystack, string $needle)`
- `stri_starts_with(string $haystack, string $needle)`
- `stri_contains(string $haystack, string $needle)`
---

### 📄 cmsb/lib/array_functions.php
- `array_first($array)`
- `array_groupBy($recordList, $indexField, $resultsAsArray = false)`
- `array_keys_prefix(string $prefix, array $array)`
- `array_pluck($recordList, $targetField)`
- `array_slice_keys($array, $keys)`
- `array_value(array $array, ...$keys)`
- `array_where($records, $conditions)`
---

### 📄 cmsb/lib/Struct.php
- `load(string $filepath)`
- `save(string $filepath, array $struct, string $headerMessage = '')`
- `isPhpFile($filepath)`
- `loadPhpFile(string $filepath)`
- `savePhpFile(string $filepath, array $struct, string $headerMessage = '')`
- `getPhpHeader(bool $short = false)`
- `invalidatePhpFileOpcache($filepath)`
- `isIniFile(string $filepath)`
- `loadIniFile($filepath, bool $updateFile = false)`
---

### 📄 cmsb/lib/upload_functions.php
- `upload_filePath_fields()`
- `upload_urlPath_fields()`
- `addUploadsToRecords(&$rows, $tableName = null, $debugSql = FALSE, $preSaveTempId = null)`
- `addUploadsToRecord(&$record, $tableName = null, $debugSql = FALSE, $preSaveTempId = null)`
- `removeUpload($uploadNum, $recordNum, $preSaveTempId)`
- `removeUploadsFor($tableName, $recordNum)`
- `removeUploads($where)`
- `getUploadInfoArrays()`
- `saveUploadFromFilepath($tablename, $fieldname, $recordNum, $preSaveTempId, $filepath)`
- `saveUpload($tablename, $fieldname, $recordNum, $preSaveTempId, $uploadInfo, &$newUploadNums, $skipUploadSecurityCheck = false)`
- `_saveUpload_getExtensionFromFileName($uploadName)`
- `_saveUpload_getExtensionFromFileData( $uploadFilepath )`
- `_saveUpload_hasValidExt($uploadName, $fieldSchema)`
- `_saveUpload_allowAllExt($fieldSchema)`
- `_saveUpload_processChunking(&$uploadInfo, $workingDir, $fieldSchema, $skipUploadSecurityCheck)`
- `_saveUpload_moveTempUploadFile($uploadedAsFilename, $targetDir, $skipUploadSecurityCheck)`
- `_saveUpload_fixFilePermission($filePath)`
- `_saveUpload_appendChunk($saveAsFilepath, $uploadInfo, $fieldSchema)`
- `_saveUpload_checkFileIsValid($uploadFilepath, $uploadInfo)`
- `_saveUpload_getErrors($tableName, $fieldname, $uploadInfo, $recordNum, $preSaveTempId)`
- `_saveUpload_validateUploadFileExt($uploadInfo, $fieldSchema, $mainUploadWorkingPath)`
- `_saveUpload_getTargetBasenameAndExtension($uploadedAsFilename)`
- `_saveUpload_chooseUniqueNumberedFilename($uploadedAsFilename, $uploadDir)`
- `_saveUpload_addToDatabase($uploadRecordDetails, $fieldSchema)`
- `adoptUploads(string $tableName, $preSaveTempId, $newRecordNum)`
- `updateUploadCounts($tableName, $recordNum)`
- `getUploadRecords($tablename, $fieldname, $recordNum, $preSaveTempId = "", $uploadNumsAsCSV = null)`
- `_addUploadPseudoFields( &$record, $schema, $fieldname )`
- `getUploadCount($tableName, $fieldName, $recordNum, $preSaveTempId)`
- `removeExpiredUploads()`
- `getUploadDirAndUrl($fieldSchema, $settingsUploadDir = null, $settingsUploadUrl = null, $returnOnErrors = false)`
- `getUploadPathPreview($dirOrUrl, $inputValue, $isCustomField, $forAjax = false)`
- `getMediaPathPreview($dirOrUrl, $inputValue, $isCustomField, $forAjax = false)`
- `_getThumbFieldSuffixes()`
- `_getThumbDetails($suffix, $fieldSchema)`
- `_getUploadUrlFromPath($fieldSchema, $filepath)`
- `getUploadLimits($tablename, $fieldname, $num, $preSaveTempId)`
- `eraseRecordsUploads($recordNumsAsCSV)`
- `eraseUpload()`
- `makeAllUploadRecordsRelative()`
- `removeUploadPathPrefix($path, $pathPrefix)`
- `addUploadPathPrefix($path, $pathPrefix)`
- `recreateThumbnails()`
- `showUploadPreview($uploadRecord, $maxWidth = 50, $maxHeight = null)`
- `getUploadInfoFields($fieldname)`
- `schemaFileExtForUploadify($allowedExtensions)`
- `fileUploadMaxSize()`
- `parseIniSize($size)`
---

### 📄 cmsb/lib/helpers.php
- `settings(string $key)`
- `forwardSlashes(string|null|false $path)`
- `request(?string $key = null, bool $allowArray = false)`
- `requestKey(?string $key = null)`
- `inCLI()`
- `isHTTPS()`
- `isWindows()`
- `isMac()`
---

### 📄 cmsb/lib/mysql_functions.php
- `mysql_escape(string|int|float|bool|null $input, bool $escapeLikeWildcards = false)`
- `mysql_escapeLikeWildcards($string)`
- `mysql_escapef()`
- `mysqlStrictMode($strictMode)`
- `mysql_limit($perPage, $pageNum)`
- `mysql_count($tableName, $whereEtc = 'TRUE')`
- `mysql_get_lock($lockName, $timeout = 0)`
- `mysql_release_lock($lockName)`
- `mysql_datetime($timestamp = null)`
- `mysql_escapeCSV($valuesArray, $defaultValue = '0')`
- `mysql_get($tableName, $recordNum, $customWhere = null)`
- `mysql_select($tableName, $whereEtc = 'TRUE')`
- `mysql_delete($tableName, $recordNum, $customWhere = null)`
- `mysql_update($tableName, $recordNum, $customWhere, $colsToValues)`
- `mysql_insert($tableName, $colsToValues, $tempDisableMysqlStrictMode = false)`
- `_mysql_getWhereFromNumAndCustomWhere($recordNum, $customWhere)`
- `mysql_set($columnsToValues)`
- `mysql_where($criteriaArray = null, $extraWhere = 'TRUE')`
- `_mysql_upgradeTablesToUTF8mb4($force = false)`
- `__mysql_upgradeTableToUTF8mb4($mysqlTable, $force = false)`
- `mysql_encrypt_column($tableName, $colName)`
- `mysql_decrypt_column($tableName, $colName)`
- `mysql_decrypt_addSelectExpr($tableName, $schema = [], $tableAlias = '')`
- `mysql_decrypt_getColumnsNamesOrExpr($tablenameOrSchema, $colNames, $tableAlias = '', $outputUnencryptedColExpr = true)`
- `_mysql_encrypt_valueExpr($value, $isValueEscapedAndQuoted = false)`
- `_mysql_encrypt_columnExpr($colName)`
- `_mysql_decrypt_columnExpr($colName)`
- `mysql_encrypt_listColumns($tableName = '')`
- `_mysql_encryption_key()`
- `_mysql_encryption_colType()`
- `mysql_encryptExpr_colsToValues($tableName, $colsToValues)`
- `mysql_isSupportedColumn($tableName, $colname)`
- `_mysql_convertTablesToInnoDB()`
---

### 📄 cmsb/lib/shell_functions.php
- `shellCommand(string $command, ?int &$exitCode = null, ?string &$functionUsed = null)`
- `_shellCommand_exec(string $command, ?int &$exitCode = null, ?string &$functionUsed = null)`
- `_shellCommand_system(string $command, ?int &$exitCode = null, ?string &$functionUsed = null)`
- `_shellCommand_passthru(string $command, ?int &$exitCode = null, ?string &$functionUsed = null)`
---

### 📄 cmsb/lib/ZenDB/MysqliWrapper.php
- `setLastQuery(string $query)`
- `getLastQuery()`
- `real_connect(
        #[\SensitiveParameter] ?string $hostname = null,
        #[\SensitiveParameter] ?string $username = null,
        #[\SensitiveParameter] ?string $password = null,
        ?string $database = null,
        ?int $port = null,
        ?string $socket = null,
        int $flags = 0
    )`
- `query(string $query, int $result_mode = MYSQLI_STORE_RESULT)`
- `real_query(string $query)`
- `multi_query(string $query)`
- `prepare(string $query)`
- `initializeLogging()`
- `logError(string $message, ?int $code = null, ?\throwable $e = null)`
- `logQuery(?float $startTime, string $query)`
- `hideSensitiveData(string $query)`
---

### 📄 cmsb/lib/ZenDB/Parser.php
- `__construct()`
- `setSqlTemplate(string $sqlTemplate)`
- `addParamsFromArgs(array $methodParams)`
- `addPositionalParam(string|int|float|bool|null|RawSql $value)`
- `addNamedParam(string $name, string|int|float|bool|null|RawSql $value)`
- `addInternalParam(string $name, string|int|float|bool|null|RawSql $value)`
- `addParam(string $name, string|int|float|bool|null|RawSql|SmartString $value)`
- `getEscapedQuery()`
- `getParamQuery()`
- `getBindValues()`
- `getPlaceholderRegexp()`
- `getPlaceholderValue($matchedString, &$positionalCount)`
- `replaceParam($value, &$bindValues)`
- `replaceParamInBackticks($replacementValue)`
- `throwIfQueryFinalized()`
- `isDmlQuery()`
- `getSqlTemplate()`
---

### 📄 cmsb/lib/ZenDB/DBException.php
- `__construct(string $message = "", int $code = 0, ?Throwable $previous = null)`
---

### 📄 cmsb/lib/ZenDB/DebugInfo.php
- `throwUnknownMethodException(string $method, string $class, ?array $excludedMethods = [])`
- `logDeprecatedError($error)`
- `getPublicMethods(string $class, ?array $excludeMethods = [])`
- `getCallerVarName()`
- `getFunctionArgsFromLine($phpCodeLine, $functionName)`
- `getHelpMethodChainPrefix($phpCodeLine)`
- `xmpWrap($output)`
- `getOutputAsDebugInfoArray(string $output)`
- `getPrettyVarValue($value)`
- `getPrettyVarDump($var)`
- `inCallStack($function)`
---

### 📄 cmsb/lib/ZenDB/Config.php
- `get(string $key)`
- `getAll()`
- `set(string $key, bool|string|int|callable|null $value)`
- `config(array $config)`
- `getPostConnectKeys()`
- `getValidPropertyTypes($property)`
---

### 📄 cmsb/lib/ZenDB/RawSql.php
- `__construct(string $value)`
- `__toString()`
---

### 📄 cmsb/lib/ZenDB/Assert.php
- `type(mixed $value, array $allowedTypes, ?string $name = null)`
- `notType(mixed $value, array $disallowedTypes, ?string $name = null)`
- `validDatabaseName(string $identifier)`
- `validTableName(string $identifier)`
- `validColumnName(string $identifier)`
- `sqlSafeString(string $string, ?string $inputName = null, $allowNumbers = false)`
- `validConfig(string $key, mixed $value)`
- `encodableType(mixed $input)`
- `mysqlVersion(mysqli $mysqli, string $requiredVersion)`
---

### 📄 cmsb/lib/ZenDB/DB.php
- `config(string|array|null $keyOrArray = null, string|int|bool|null $keyValue = null)`
- `connect()`
- `isConnected(bool $doPing = false)`
- `disconnect()`
- `setDatabaseVars(mysqli $mysqli, array $cfg)`
- `selectOrCreateDatabase(mysqli $mysqli, array $cfg)`
- `query(string $sqlTemplate, ...$params)`
- `select(string $baseTable, int|array|string $idArrayOrSql = [], ...$params)`
- `get(string $baseTable, int|array|string $idArrayOrSql = [], ...$params)`
- `insert(string $baseTable, array $colsToValues)`
- `update(string $baseTable, array $colsToValues, int|array|string $idArrayOrSql, ...$params)`
- `delete(string $baseTable, int|array|string $idArrayOrSql, ...$params)`
- `count(string $baseTable, int|array|string $idArrayOrSql = [], ...$params)`
- `getWhereEtc(int|array|string $idArrayOrSql, bool $whereRequired = false)`
- `getWhereEtcForArray(array $idArrayOrSql)`
- `getSetClause(array $colsToValues)`
- `debug()`
- `rawSql(string|int|float|null $value)`
- `isRawSql(mixed $stringOrObj)`
- `pagingSql(mixed $pageNum, mixed $perPage = 10)`
- `datetime(?int $unixTime = null)`
- `escapeCSV(array $array)`
- `escapeLikeWildcards(string|int|float|null $keyword)`
- `getBaseTable(string $fullOrBaseTable)`
- `getFullTable(string $fullOrBaseTable)`
- `setTimezoneToPhpTimezone(string $mysqlTzOffset = '')`
- `tableExists(string $tableName)`
- `fetchResultSet(string $baseTable = '')`
- `mysqliPrepareBindExecute()`
- `__destruct()`
- `fetchRows(bool|mysqli_result|MysqliStmtResultEmulator $mysqliResult)`
- `getColumnNameToIndex(mysqli_result|MysqliStmtResultEmulator $mysqliResult)`
- `loadNextRow(mysqli_result|MysqliStmtResultEmulator $mysqliResult, array $colNameToIndex)`
- `__construct()`
- `__callStatic(string $name, array $args)`
- `raw(...$args)`
---

### 📄 cmsb/lib/ZenDB/MysqliStmtResultEmulator.php
- `__construct(mysqli_stmt $stmt)`
- `fetch_fields()`
- `fetch_array(int $mode = MYSQLI_BOTH)`
- `fetch_assoc()`
- `fetch_row()`
- `free()`
- `__get(string $name)`
- `__call($name, $arguments)`
---

### 📄 cmsb/lib/ZenDB/MysqliStmtWrapper.php
- `__construct(MysqliWrapper $mysqliWrapper, string $query, float $startTime)`
- `bind_param($types, &...$params)`
- `execute(?array $params = null)`
---

### 📄 cmsb/lib/menus/install.php
- `getContent()`
---

### 📄 cmsb/lib/menus/footer.php
- `phpConstant(cname)`
---

### 📄 cmsb/lib/menus/header_functions.php
- `getMenuLinks()`
- `_openMenuGroupList($menuGroupName, $isSelected, $liClass, $skipIfAlreadyInGroup = false, $isMyAccountMenu = false)`
- `_closeMenuGroupList()`
- `_userHasMenuAccess($menu)`
- `_getMenuList()`
- `_getAdminMenus(&$menuOrder)`
- `_fixOrphanMenuItems($menus)`
- `_getMyAccountMenus()`
- `getMyAccountMenu_AsTextLinks()`
---

### 📄 cmsb/lib/menus/database/editField_functions.php
- `getTablesAndFieldnames()`
- `getFieldAttributes($fieldname)`
- `submitFormViaAjax()`
- `_updateSchema(array $schema, $doSaveSchema = true)`
- `_updateMySQL($schema, $targetSchema)`
- `getSetValueForNewColumn()`
- `ajaxHandlerForeignKey()`
---

### 📄 cmsb/lib/menus/database/editField.php
- `_getContent($field)`
---

### 📄 cmsb/lib/menus/database/actionHandler.php
- `updateTableOrder()`
- `addTable()`
- `getSchemaPresets()`
- `previewDefaultDate()`
---

### 📄 cmsb/lib/menus/database/addTable.php
- `showPresetOptions()`
- `showCopyOptions()`
- `_updateAdvancedDescription(advancedType)`
---

### 📄 cmsb/lib/menus/database/editTable.php
- `dispatchRequest()`
- `renderDefaultView()`
- `getViewVars()`
- `setNoticesAndAlerts()`
- `listFields($exitAfter = false)`
- `saveTableDetails()`
- `updateFieldOrder()`
- `allowSystemFieldEditing(bool $enable)`
- `eraseField()`
- `dropTable()`
- `showFieldLabel($fieldSchema)`
- `showFieldType($fieldSchema)`
- `showMySqlType($fieldSchema, $mysqlColumns)`
- `getMySqlTypeFkDetails($fieldSchema)`
- `showActions($fieldSchema)`
- `getFkColumnToReference($fullTable)`
---

### 📄 cmsb/lib/menus/database/listTables_functions.php
- `getTableList()`
---

### 📄 cmsb/lib/menus/database/listTables.php
- `_getContent()`
---

### 📄 cmsb/lib/menus/_log_audit/actionHandler.php
- `_auditlog_showModeNotice($tableName, $action)`
- `_auditLog_cmsList_detailsColumn($displayValue, $tableName, $fieldname, $record = [])`
---

### 📄 cmsb/lib/menus/_error_log/actionHandler.php
- `_pel_showModeNotice($tableName, $action)`
- `_pel_cmsList_messageColumn($displayValue, $tableName, $fieldname, $record = [])`
- `errorLog_errorsByFilepath()`
- `errorLog_errorsByFilepath_listContent()`
- `confirmClearErrors(e, filepath, lineNum)`
- `errorLog_latestError()`
---

### 📄 cmsb/lib/menus/admin/branding.php
- `_getContent()`
---

### 📄 cmsb/lib/menus/admin/backgroundTasks.php
- `_getPreFormContent()`
- `_getContent()`
---

### 📄 cmsb/lib/menus/admin/emailSettings.php
- `renderDefaultView()`
- `getPreFormContent()`
- `saveAndRequestToken()`
- `getTokenInfo()`
- `sendTestEmail()`
- `saveEmailSettings()`
---

### 📄 cmsb/lib/menus/admin/general_server_info.php
- `__serverInfo_contentDeliveryNetwork()`
- `__serverInfo_webServer()`
- `__serverInfo_operatingSystem()`
- `__serverInfo_databaseServer()`
- `__serverInfo_databaseServer_privilegesHTML()`
- `__serverInfo_phpVersion()`
- `__serverInfo_recentChanges()`
- `___html_content_below___()`
---

### 📄 cmsb/lib/menus/admin/plugins.php
- `wrapServerInfoText(text)`
---

### 📄 cmsb/lib/menus/admin/sqlMonitor.php
- `processAjaxRequest()`
- `sqlMonitor_loadLines($logFile, $offset)`
- `sqlMonitor_filterLine($line)`
- `filterButton(string $label, string $filterName, bool $value)`
---

### 📄 cmsb/lib/menus/admin/backupAndRestore.php
- `renderDefaultView()`
- `webBackup()`
- `createZipArchive(string $zipFilePath, string $webRoot, string $dataDir, bool $onlyCodeFiles)`
- `getBackupFilename(?string $backupDesc, bool $includeCodeOnly, bool $skipDatabase)`
- `webDownload()`
- `getPreviousBackupFiles()`
- `getPatternsRegexp(array $patterns)`
- `excludePatterns()`
- `includePatternsForCodeOnly()`
- `dbBackup()`
- `dbRestore()`
- `dbRestoreComplete()`
- `dbDownload()`
---

### 📄 cmsb/lib/menus/admin/pluginHooks.php
- `_getContent()`
- `_sortUnderscoresLast($a, $b)`
- `showListResultsForHookKey($hookInfo, $key)`
- `showHookTable($hooks)`
---

### 📄 cmsb/lib/menus/admin/plugins_list.php
- `outputListContent()`
- `_sortPluginsByName($arrayA, $arrayB)`
- `showPluginList($listType)`
- `_showPluginRow($pluginType, $pluginData)`
- `_showPluginActions($pluginData)`
---

### 📄 cmsb/lib/menus/admin/actionHandler.php
- `admin_dispatchAction($action)`
- `admin_saveSettings($savePagePath)`
- `getAjaxDatePreview()`
- `admin_phpinfo()`
- `admin_ulimit()`
- `admin_diskuse()`
- `admin_plugins()`
- `admin_deactivatePlugin()`
- `admin_activatePlugin()`
- `admin_bgtasksLogsClear()`
- `getTimeZoneOptions(string $selectedTimezone = '')`
- `posix_getrlimit()`
- `getUlimitValues($type = 'soft')`
- `admin_db_show_variables($status = false)`
---

### 📄 cmsb/lib/menus/admin/backupAndRestore.ajax.php
- `getBackupSize()`
- `getFileStats(array $dirs)`
- `getDatabaseStats()`
- `getPreviousBackupList()`
---

### 📄 cmsb/lib/menus/admin/general.php
- `_getPreFormContent()`
- `_getContent()`
---

### 📄 cmsb/lib/menus/admin/security.php
- `_getContent()`
---

### 📄 cmsb/lib/menus/default/uploadForm_functions.php
- `submitUploadForm()`
- `_showWysiwygUploadPreview($row, $maxWidth = 150, $maxHeight = 125)`
- `_showLinks($row)`
---

### 📄 cmsb/lib/menus/default/edit_functions.php
- `showFields($record)`
---

### 📄 cmsb/lib/menus/default/mediaList.php
- `addMedia(mediaNum)`
---

### 📄 cmsb/lib/menus/default/wysiwygMedia.php
- `addMedia(mediaNum)`
---

### 📄 cmsb/lib/menus/default/uploadModify_functions.php
- `saveUploadDetails()`
---

### 📄 cmsb/lib/menus/default/list.php
- `jumpToPage(currentPage, totalPages, menu)`
- `listPageContent($listFields, $records, $metaData)`
---

### 📄 cmsb/lib/menus/default/list_functions.php
- `list_functions_init($options = [])`
- `getSchemaListPageFields($schema)`
- `listPageFieldsHaveUploadField($listFields, $schema)`
- `showListTable($listFields, $records, $options = [])`
- `redirectSingleRecordAuthorsToEditPage()`
- `getSearchField($searchRow, $isPrimarySearchField = false)`
- `_parseSearchFieldsFormat($searchFieldsFormat)`
- `functionName()`
- `__getAllSearchableFieldsAsCSV(&$schema)`
- `displayColumnHeaders($listFields, $isRelatedRecords = false)`
- `_getFieldLabel($fullFieldname)`
- `displayListColumns($listFields, $record, $options = [])`
- `_getColumnDisplayValueAndAttributes($fieldname, &$record)`
- `_getListOptionLabelByValue($fieldSchema, $record)`
- `getPaginationHTML($metaData, $position = null)`
---

### 📄 cmsb/lib/menus/default/actionHandler.php
- `loginAsUser(bool $loginToWebsite = false)`
- `ajaxUpdateListFieldOptions()`
- `_displayRequiredPluginErrors()`
- `displaySectionAccessErrors($action)`
- `_displayRecordAccessErrors($action)`
- `_showIframeSections()`
---

### 📄 cmsb/lib/menus/default/view.php
- `showViewFormRows($record)`
---

### 📄 cmsb/lib/menus/default/wysiwygUploads.php
- `showHideNoUploadsMessage()`
- `removeUpload(uploadNum, filename, rowChildEl)`
- `insertUpload(newValue, isImage)`
---

### 📄 cmsb/lib/menus/default/common.php
- `ajaxGetUsersAsPulldown()`
- `listDragSort()`
- `eraseRecords()`
- `showMaxRecordsError($returnText = false)`
- `uploadListReOrder()`
- `updateCategoryMetadata()`
- `updateCategoryMetadataDrag()`
- `_updateCategoryBranch($args)`
- `_updateCategoryBranchDrag($args)`
- `_sortCategoriesBySiblingOrder($arrayA, $arrayB)`
- `categoryMove()`
- `categoryMoveDrag()`
- `category_exceedMaxDepth($currentDepth, $deepestDepth, $targetParentCategoryRecord = [], $maxDepth = 0)`
---

### 📄 cmsb/lib/menus/default/save.php
- `_getInputValidationErrors($newRecordValues)`
- `_getColsToValuesForSQLSet($mySqlColsAndTypes, $newRecordValues, $isInsert = false, array $oldRecord = [])`
- `_updateAccessList()`
- `getErrorForMysqlErrno(int $mysqlErrno, string $mysqlError)`
---

### 📄 cmsb/lib/menus/_media/actionHandler.php
- `media_cmsList_uploadSave()`
- `media_cmsList_uploadBox()`
- `media_cmsList_uploadBox_placeholder()`
- `media_cmsList_messageColumn($displayValue, $tableName, $fieldname, $record = [])`
- `media_preErase($tableName, $recordNumsAsCSV)`
---

### 📄 cmsb/lib/menus/_codeGenerator/comboPage.php
- `cg2_combopage($function, $name, $description, $type)`
- `cg2_combopage_getOptions($function, $name, $description, $type)`
- `cg2_combopage_getCode()`
- `cg2_combopage_ajaxJsCode()`
- `cg2_updateSchemaFieldPulldowns()`
- `cg2_combopage_ajaxPhpCode()`
---

### 📄 cmsb/lib/menus/_codeGenerator/detailPage.php
- `cg2_detailpage($function, $name, $description, $type)`
- `cg2_detailpage_getOptions($function, $name, $description, $type)`
- `cg2_detailpage_getCode()`
---

### 📄 cmsb/lib/menus/_codeGenerator/rssFeed.php
- `cg2_rssfeed($function, $name, $description, $type)`
- `cg2_rssfeed_getOptions($function, $name, $description, $type)`
- `cg2_rssfeed_getCode()`
- `cg2_rssfeed_ajaxJsCode()`
- `cg2_updateSchemaFieldPulldowns()`
- `cg2_rssfeed_ajaxPhpCode()`
---

### 📄 cmsb/lib/menus/_codeGenerator/generator_functions.php
- `cg_typeByVersion($version)`
- `cg2_header($function, $name)`
- `cg2_footer()`
- `cg_adminUI($adminUI, $title = '', $function = '')`
- `cg2_showCode($function, $name, $instructions, $suffix, $code)`
- `cg2_inputText($name, $size = 3, $addFormControlClass = false)`
- `cg2_inputRadio($name, $value)`
- `cg2_inputCheckbox($name)`
- `cg2_inputSchemaField($fieldname)`
- `cg2_inputSchemaField_getOptions($tableName, $fieldname = '')`
- `cg2_option_selectSection($allowedMenuTypes = [])`
- `cg2_option_sorting()`
- `cg2_option_uploads()`
- `cg2_code_loadLibraries()`
- `cg2_code_header()`
- `cg2_code_instructions($viewerType)`
- `cg2_code_schemaFields($schema, $varName, $tableName)`
- `cg2_code_uploads($schema, $varName)`
- `cg2_code_footer()`
---

### 📄 cmsb/lib/menus/_codeGenerator/listPage.php
- `cg2_listpage($function, $name, $description, $type)`
- `cg2_listpage_getOptions($function, $name, $description, $type)`
- `cg2_listpage_getCode()`
---

### 📄 cmsb/lib/menus/_codeGenerator/actionHandler.php
- `cg2_homepage($error = '')`
- `_cg2_getGeneratorList($heading, $description, $type)`
---

### 📄 cmsb/lib/menus/_codeGenerator/categoryMenu.php
- `cg2_categorypage($function, $name, $description, $type)`
- `cg2_categorypage_getOptions($function, $name, $description, $type)`
- `cg2_categorypage_ajaxJsCode()`
- `cg2_updateSchemaFieldPulldowns(fieldname)`
- `cg2_categorypage_ajaxPhpCode()`
- `cg2_categorypage_getCode()`
- `myUlAttr($category)`
- `myLiAttr($category)`
- `__getCategoryNames_asSelectOptions($fieldname)`
---

### 📄 cmsb/lib/menus/_cron_log/actionHandler.php
- `_cronlog_showModeNotice($tableName, $action)`
- `_cronlog_clearLog($tableName, $action)`
---

### 📄 cmsb/lib/menus/_email_templates/actionHandler.php
- `emailTemplatesMenu_addAdvancedOption($labelsToValues)`
- `_emt_cmsList_customWysiwyg($tableName, $recordNum)`
- `_emt_cmsList_messageColumn($displayValue, $tableName, $fieldname, $record = [])`
- `emailTemplatesMenu_exportTemplatesPHP()`
- `emailTemplatesMenu_showSendMessagePHP()`
---

### 📄 cmsb/lib/menus/_outgoing_mail/actionHandler.php
- `_ogm_cmsList_customWysiwyg($tableName, $recordNum)`
- `_ogm_cmsList_messageColumn($displayValue, $tableName, $fieldname, $record = [])`
- `_ogm_showModeNotice($tableName, $action)`
---

### 📄 cmsb/lib/menus/_sessions/actionHandler.php
- `dispatchRemoveActions()`
- `showPageNotice($tableName, $action)`
- `modifyListHeaderLabels($label, $tableName, $fieldname)`
- `modifyListRowValues($displayValue, $tableName, $fieldname/* , $record = [] */)`
---

### 📄 cmsb/lib/Fields/Wysiwyg.php
- `getEditComponent()`
- `addJsIncludesToFooter()`
- `jsFormSubmitEventListener()`
- `getLengthErrors(?int $length = null)`
---

### 📄 cmsb/lib/Fields/DateTime.php
- `getRequestValue(?bool $usePreviewPrefix = false)`
- `getDefaultValue()`
- `getEditRow()`
- `getViewValue()`
- `getRequiredErrors()`
- `getUniqueErrors()`
- `getDateTimeFormat()`
- `isPartialDateEntered()`
---

### 📄 cmsb/lib/Fields/Factory.php
- `create(string $name = '', array $schema = [], array $record = [])`
---

### 📄 cmsb/lib/Fields/TextBox.php
- `getRequestValue(?bool $usePreviewPrefix = false)`
- `getEditRow()`
- `getEditComponent()`
- `getViewValue()`
- `getLengthErrors(?int $length = null)`
---

### 📄 cmsb/lib/Fields/ForeignKey.php
- `getRequestValue(?bool $usePreviewPrefix = false)`
- `getViewValue()`
- `getListValue()`
- `getEditComponent()`
- `processAjaxRequest()`
- `getValidationErrors()`
- `getRequiredErrors()`
- `getInsertValueExpr()`
- `getInsertValueDefault()`
- `getUpdateValueExpr()`
- `dropIndexes()`
- `createIndex()`
- `getColumnType()`
- `getPrimaryKeyColumnType()`
- `dropConstraints()`
- `addConstraint()`
- `getConstraintNames()`
- `getFkLabelFromDbValue()`
---

### 📄 cmsb/lib/Fields/TabGroup.php
- `getEditRow()`
- `getViewRow()`
- `getEditRowFinal()`
- `tabGroupStart()`
- `tabPanelStart(bool $isFirst = false)`
- `tabPanelEnd()`
- `tabGroupEnd()`
---

### 📄 cmsb/lib/Fields/GeneratedColumn.php
- `getColumnType()`
---

### 📄 cmsb/lib/Fields/ParentCategory.php
- `getEditComponent()`
---

### 📄 cmsb/lib/Fields/RelatedRecords.php
- `getEditRow()`
- `getViewRow()`
- `relatedRecordsButton($label, $url, $addReturnUrl = true)`
---

### 📄 cmsb/lib/Fields/Special.php
- `getEditRow()`
- `getViewRow()`
---

### 📄 cmsb/lib/Fields/DateCalendar.php
- `getRequestValue(?bool $usePreviewPrefix = false)`
- `getEditRow()`
- `getViewRow()`
- `getEditComponent()`
- `_createEditCalendar($fieldname, $monthNum, $year, $selectedDates)`
- `_updateDateCalendar($fieldname)`
---

### 📄 cmsb/lib/Fields/Upload.php
- `getEditComponent()`
- `getRequiredErrors()`
- `getInsertValueExpr()`
- `getInsertValueDefault()`
- `getUpdateValueExpr()`
- `alterColumn()`
- `renameOrDeleteUploads()`
---

### 📄 cmsb/lib/Fields/InputHidden.php
- `getEditRow()`
- `getViewRow()`
---

### 📄 cmsb/lib/Fields/TextField.php
- `getValue()`
- `getEditComponent()`
- `getListValue()`
- `getViewValue()`
- `getValidationErrors()`
- `getRequiredErrors()`
- `getUniqueErrors()`
- `getInsertValueExpr()`
- `getInsertValueDefault()`
- `getUpdateValueExpr()`
- `isInternalPasswordField()`
- `getPasswordHashOrNull()`
- `isMyAccountMenu()`
- `getMyAccountPasswordValidationErrors()`
- `getAccountPasswordValidationErrors()`
- `isInternalEmailOrUsername()`
- `getEmailOrUsernameUnavailableErrors()`
---

### 📄 cmsb/lib/Fields/AccessList.php
- `getEditRow()`
- `getEditComponent()`
- `toggleDisabledForAccessListMaxRecords(tablename)`
---

### 📄 cmsb/lib/Fields/ListField.php
- `getRequestValue(?bool $usePreviewPrefix = false)`
- `getEditComponent()`
- `getViewValue()`
- `getEditComponentPulldownSingle()`
- `getEditComponentPulldownMulti()`
- `getEditComponentPulldownRadios()`
- `getEditComponentPulldownCheckboxes()`
- `getEditComponentFilterScript()`
- `createListProperties()`
---

### 📄 cmsb/lib/Fields/Checkbox.php
- `getDescription(?string $class = "help-block")`
- `getDefaultValue()`
- `getEditRow()`
- `getEditComponent()`
- `getViewValue()`
- `getInsertValueExpr()`
- `getInsertValueDefault()`
- `getUpdateValueExpr()`
---

### 📄 cmsb/lib/Fields/None.php
- `getRequestValue(?bool $usePreviewPrefix = false)`
- `getEditRow()`
- `getViewRow()`
- `getValidationErrors()`
- `getInsertValueExpr()`
- `getInsertValueDefault()`
- `getUpdateValueExpr()`
---

### 📄 cmsb/lib/Fields/Separator.php
- `getEditRow()`
- `getViewRow()`
---

### 📄 cmsb/lib/Fields/BaseField.php
- `__construct(string $name, array $schema, array $record)`
- `getDatabaseValue()`
- `getRequestValue(?bool $usePreviewPrefix = false)`
- `getDefaultValue()`
- `getValue()`
- `getLabel()`
- `getPrefix(?string $class = "help-block")`
- `getDescription(?string $class = "help-block")`
- `getEditRow()`
- `getEditRowFinal()`
- `getEditComponent()`
- `getViewRow()`
- `getViewValue()`
- `getListValue()`
- `getWebValue()`
- `addJsIncludesToFooter()`
- `processAjaxRequest()`
- `getValidationErrors()`
- `getRequiredErrors()`
- `getUniqueErrors()`
- `getLengthErrors(?int $length = null)`
- `getCharsetErrors()`
- `getErrorText($format, ...$args)`
- `getInsertValueExpr()`
- `getInsertValueDefault()`
- `getUpdateValueExpr()`
- `createField(BaseField $targetState, ?string $setValue = null)`
- `modifyField(BaseField $targetState)`
- `deleteField()`
- `alterColumn()`
- `getIndexNames()`
- `dropIndexes()`
- `createIndex()`
- `getColumnType()`
- `getColumnTypeFromMySQL(string $colName)`
---

### 📄 cmsb/lib/Fields/SpecialFieldnames/updatedByUserNum.php
- `getDefaultValue()`
- `getInsertValueExpr()`
- `getInsertValueDefault()`
- `getUpdateValueExpr()`
---

### 📄 cmsb/lib/Fields/SpecialFieldnames/siblingOrder.php
- `getDefaultValue()`
- `getInsertValueExpr()`
- `getInsertValueDefault()`
- `getUpdateValueExpr()`
---

### 📄 cmsb/lib/Fields/SpecialFieldnames/createdDate.php
- `getRequestValue(?bool $usePreviewPrefix = false)`
- `getEditRow()`
- `getEditComponent()`
- `getViewValue()`
- `getInsertValueExpr()`
- `getInsertValueDefault()`
- `getUpdateValueExpr()`
- `getFormattedDate()`
- `getUserName()`
---

### 📄 cmsb/lib/Fields/SpecialFieldnames/dragSortOrder.php
- `getDefaultValue()`
- `getEditRow()`
- `getViewRow()`
- `getValidationErrors()`
---

### 📄 cmsb/lib/Fields/SpecialFieldnames/createdByUserNum.php
- `getRequestValue(?bool $usePreviewPrefix = false)`
- `getDefaultValue()`
- `getInsertValueExpr()`
- `getInsertValueDefault()`
- `getUpdateValueExpr()`
---

### 📄 cmsb/lib/Fields/SpecialFieldnames/updatedDate.php
- `getRequestValue(?bool $usePreviewPrefix = false)`
- `getEditRow()`
- `getEditComponent()`
- `getViewValue()`
- `getInsertValueExpr()`
- `getInsertValueDefault()`
- `getUpdateValueExpr()`
- `getFormattedDate()`
- `getUserName()`
---

### 📄 cmsb/3rdParty/HTMLPurifier/HTMLPurifier.standalone.php
- `__construct($config = null)`
- `addFilter($filter)`
- `purify($html, $config = null)`
- `purifyArray($array_of_html, $config = null)`
- `instance($prototype = null)`
- `getInstance($prototype = null)`
- `arborize($tokens, $config, $context)`
- `flatten($node, $config, $context)`
- `__construct($attr_types, $modules)`
- `doConstruct($attr_types, $modules)`
- `performInclusions(&$attr)`
- `expandIdentifiers(&$attr, $attr_types)`
- `validate($string, $config, $context)`
- `parseCDATA($string)`
- `make($string)`
- `mungeRgb($string)`
- `expandCSSEscape($string)`
- `transform($attr, $config, $context)`
- `prependCSS(&$attr, $css)`
- `confiscateAttr(&$attr, $key)`
- `__construct()`
- `makeEnum($in)`
- `get($type)`
- `set($type, $impl)`
- `validateToken($token, $config, $context)`
- `autoload($class)`
- `getPath($class)`
- `registerAutoload()`
- `doSetup($config)`
- `setup($config)`
- `doSetup($config)`
- `doSetupProprietary($config)`
- `doSetupTricky($config)`
- `doSetupTrusted($config)`
- `setupConfigStuff($config)`
- `getAllowedElements($config)`
- `validateChildren($children, $config, $context)`
- `__construct($definition, $parent = null)`
- `create($config, $schema = null)`
- `inherit(HTMLPurifier_Config $config)`
- `createDefault()`
- `get($key, $a = null)`
- `getBatch($namespace)`
- `getBatchSerial($namespace)`
- `getSerial()`
- `getAll()`
- `set($key, $value, $a = null)`
- `_listify($lookup)`
- `getHTMLDefinition($raw = false, $optimized = false)`
- `getCSSDefinition($raw = false, $optimized = false)`
- `getURIDefinition($raw = false, $optimized = false)`
- `getDefinition($type, $raw = false, $optimized = false)`
- `initDefinition($type)`
- `maybeGetRawDefinition($name)`
- `maybeGetRawHTMLDefinition()`
- `maybeGetRawCSSDefinition()`
- `maybeGetRawURIDefinition()`
- `loadArray($config_array)`
- `getAllowedDirectivesForForm($allowed, $schema = null)`
- `loadArrayFromForm($array, $index = false, $allowed = true, $mq_fix = true, $schema = null)`
- `mergeArrayFromForm($array, $index = false, $allowed = true, $mq_fix = true)`
- `prepareArrayFromForm($array, $index = false, $allowed = true, $mq_fix = true, $schema = null)`
- `loadIni($filename)`
- `isFinalized($error = false)`
- `autoFinalize()`
- `finalize()`
- `triggerError($msg, $no)`
- `serialize()`
- `__construct()`
- `makeFromSerial()`
- `instance($prototype = null)`
- `add($key, $default, $type, $allow_null)`
- `addValueAliases($key, $aliases)`
- `addAllowedValues($key, $allowed)`
- `addAlias($key, $new_key)`
- `postProcess()`
- `__construct($modules)`
- `generateChildDef(&$def, $module)`
- `generateChildDefCallback($matches)`
- `getChildDef($def, $module)`
- `convertToLookup($string)`
- `register($name, &$ref)`
- `destroy($name)`
- `exists($name)`
- `loadArray($context_array)`
- `__construct($type)`
- `generateKey($config)`
- `isOld($key, $config)`
- `checkDefType($def)`
- `add($def, $config)`
- `set($def, $config)`
- `replace($def, $config)`
- `get($config)`
- `remove($config)`
- `flush($config)`
- `cleanup($config)`
- `setup()`
- `instance($prototype = null)`
- `register($short, $long)`
- `create($type, $config)`
- `addDecorator($decorator)`
- `__construct(
        $name = null,
        $xml = true,
        $modules = array()`
- `register(
        $doctype,
        $xml = true,
        $modules = array()`
- `get($doctype)`
- `make($config)`
- `getDoctypeFromConfig($config)`
- `create($content_model, $content_model_type, $attr)`
- `mergeIn($def)`
- `_mergeAssocArray(&$a1, $a2)`
- `__construct()`
- `muteErrorHandler()`
- `unsafeIconv($in, $out, $text)`
- `iconv($in, $out, $text, $max_chunk_size = 8000)`
- `cleanUTF8($str, $force_php = false)`
- `unichr($code)`
- `iconvAvailable()`
- `convertToUTF8($str, $config, $context)`
- `convertFromUTF8($str, $config, $context)`
- `convertToASCIIDumbLossless($str)`
- `testIconvTruncateBug()`
- `testEncodingSupportsASCII($encoding, $bypass = false)`
- `setup($file = false)`
- `instance($prototype = false)`
- `__construct()`
- `substituteTextEntities($string)`
- `substituteAttrEntities($string)`
- `entityCallback($matches)`
- `substituteNonSpecialEntities($string)`
- `nonSpecialEntityCallback($matches)`
- `substituteSpecialEntities($string)`
- `specialEntityCallback($matches)`
- `__construct($context)`
- `send($severity, $msg)`
- `getRaw()`
- `getHTMLFormatted($config, $errors = null)`
- `_renderStruct(&$ret, $struct, $line = null, $col = null)`
- `getChild($type, $id)`
- `addError($severity, $message)`
- `preFilter($html, $config, $context)`
- `postFilter($html, $config, $context)`
- `__construct($config, $context)`
- `generateFromTokens($tokens)`
- `generateFromToken($token)`
- `generateScriptFromToken($token)`
- `generateAttributes($assoc_array_of_attributes, $element = '')`
- `escape($string, $quote = null)`
- `addAttribute($element_name, $attr_name, $def)`
- `addElement($element_name, $type, $contents, $attr_collections, $attributes = array()`
- `addBlankElement($element_name)`
- `getAnonymousModule()`
- `__construct()`
- `doSetup($config)`
- `processModules($config)`
- `setupConfigStuff($config)`
- `parseTinyMCEAllowedList($list)`
- `getChildDef($def)`
- `addElement($element, $type, $contents, $attr_includes = array()`
- `addBlankElement($element)`
- `addElementToContentSet($element, $type)`
- `parseContents($contents)`
- `mergeInAttrIncludes(&$attr, $attr_includes)`
- `makeLookup($list)`
- `setup($config)`
- `__construct()`
- `registerModule($module, $overload = false)`
- `addModule($module)`
- `addPrefix($prefix)`
- `setup($config)`
- `processModule($module)`
- `getElements()`
- `getElement($name, $trusted = null)`
- `build($config, $context)`
- `add($id)`
- `load($array_of_ids)`
- `rewindOffset($offset)`
- `getRewindOffset()`
- `prepare($config, $context)`
- `checkNeeded($config)`
- `allowsElement($name)`
- `forward(&$i, &$current)`
- `forwardUntilEndToken(&$i, &$current, &$nesting)`
- `backward(&$i, &$current)`
- `handleText(&$token)`
- `handleElement(&$token)`
- `handleEnd(&$token)`
- `notifyEnd($token)`
- `__construct($config, $context)`
- `load()`
- `getMessage($key)`
- `getErrorName($int)`
- `listify($array)`
- `formatMessage($key, $args = array()`
- `instance($prototype = null)`
- `setup()`
- `create($config, $context, $code = false)`
- `getFallbackFor($code)`
- `loadLanguage($code)`
- `__construct($n = '0', $u = false)`
- `make($s)`
- `validate()`
- `toString()`
- `getN()`
- `getUnit()`
- `isValid()`
- `compareTo($l)`
- `create($config)`
- `__construct()`
- `parseText($string, $config)`
- `parseAttr($string, $config)`
- `parseData($string, $is_attr, $config)`
- `tokenizeHTML($string, $config, $context)`
- `escapeCDATA($string)`
- `escapeCommentedCDATA($string)`
- `removeIEConditional($string)`
- `CDATACallback($matches)`
- `normalize($html, $config, $context)`
- `extractBody($html)`
- `toTokenPair()`
- `__construct($preserve = false)`
- `encode($string)`
- `normalize($string)`
- `__construct($parent = null)`
- `get($name)`
- `set($name, $value)`
- `has($name)`
- `reset($name = null)`
- `squash($force = false)`
- `getParent()`
- `setParent($plist)`
- `__construct(Iterator $iterator, $filter = null)`
- `accept()`
- `__construct($input = array()`
- `shift()`
- `push($x)`
- `isEmpty()`
- `execute($tokens, $config, $context)`
- `offsetGet($index)`
- `getAccessed()`
- `resetAccessed()`
- `parseFile($file)`
- `parseMultiFile($file)`
- `parseHandle($fh)`
- `transform($tag, $config, $context)`
- `prependCSS(&$attr, $css)`
- `__get($n)`
- `position($l = null, $c = null)`
- `rawPosition($l, $c)`
- `toNode()`
- `__construct()`
- `createStart($name, $attr = array()`
- `createEnd($name)`
- `createEmpty($name, $attr = array()`
- `createText($data)`
- `createComment($data)`
- `__construct($scheme, $userinfo, $host, $port, $path, $query, $fragment)`
- `getSchemeObj($config, $context)`
- `validate($config, $context)`
- `toString()`
- `isLocal($config, $context)`
- `isBenign($config, $context)`
- `__construct()`
- `registerFilter($filter)`
- `addFilter($filter, $config)`
- `doSetup($config)`
- `setupFilters($config)`
- `setupMemberVariables($config)`
- `getDefaultScheme($config, $context)`
- `filter(&$uri, $config, $context)`
- `postFilter(&$uri, $config, $context)`
- `prepare($config)`
- `filter(&$uri, $config, $context)`
- `__construct()`
- `parse($uri)`
- `doValidate(&$uri, $config, $context)`
- `validate(&$uri, $config, $context)`
- `instance($prototype = null)`
- `getScheme($scheme, $config, $context)`
- `register($scheme, $scheme_obj)`
- `__construct($output_precision = 4, $internal_precision = 10, $force_no_bcmath = false)`
- `convert($length, $to_unit)`
- `getSigFigs($n)`
- `add($s1, $s2, $scale)`
- `mul($s1, $s2, $scale)`
- `div($s1, $s2, $scale)`
- `round($n, $sigfigs)`
- `scale($r, $scale)`
- `parse($var, $type, $allow_null = false)`
- `parseImplementation($var, $type, $allow_null)`
- `error($msg)`
- `errorInconsistent($class, $type)`
- `errorGeneric($var, $type)`
- `getTypeName($type)`
- `__construct($front, $back)`
- `fromArray($array)`
- `toArray($t = NULL)`
- `next($t)`
- `advance($t, $n)`
- `prev($t)`
- `delete()`
- `done()`
- `insertBefore($t)`
- `insertAfter($t)`
- `splice($t, $delete, $replacement)`
- `validate($css, $config, $context)`
- `__construct($clone)`
- `validate($v, $config, $context)`
- `make($string)`
- `__construct($valid_values = array()`
- `validate($string, $config, $context)`
- `make($string)`
- `__construct($negative = true, $zero = true, $positive = true)`
- `validate($integer, $config, $context)`
- `validate($string, $config, $context)`
- `__construct($tag, $with_tag, $without_tag)`
- `validate($string, $config, $context)`
- `validate($string, $config, $context)`
- `__construct($embeds_resource = false)`
- `make($string)`
- `validate($uri, $config, $context)`
- `__construct($non_negative = false)`
- `validate($number, $config, $context)`
- `__construct()`
- `validate($number, $config, $context)`
- `__construct($config)`
- `validate($string, $config, $context)`
- `__construct()`
- `validate($string, $config, $context)`
- `__construct($config)`
- `validate($string, $config, $context)`
- `__construct()`
- `validate($color, $config, $context)`
- `__construct($defs)`
- `validate($string, $config, $context)`
- `__construct($def, $element)`
- `validate($string, $config, $context)`
- `__construct()`
- `validate($value, $config, $context)`
- `__construct($config)`
- `validate($string, $config, $context)`
- `__construct()`
- `validate($string, $config, $context)`
- `validate($string, $config, $context)`
- `__construct($def, $allow = false)`
- `validate($string, $config, $context)`
- `__construct($min = null, $max = null)`
- `validate($string, $config, $context)`
- `__construct($config)`
- `validate($string, $config, $context)`
- `__construct($single, $max = 4)`
- `validate($string, $config, $context)`
- `__construct($non_negative = false)`
- `validate($string, $config, $context)`
- `validate($string, $config, $context)`
- `__construct()`
- `validate($uri_string, $config, $context)`
- `__construct($name = false)`
- `validate($string, $config, $context)`
- `make($string)`
- `validate($string, $config, $context)`
- `split($string, $config, $context)`
- `filter($tokens, $config, $context)`
- `split($string, $config, $context)`
- `filter($tokens, $config, $context)`
- `validate($string, $config, $context)`
- `validate($string, $config, $context)`
- `__construct()`
- `validate($string, $config, $context)`
- `__construct($selector = false)`
- `validate($id, $config, $context)`
- `__construct($max = null)`
- `validate($string, $config, $context)`
- `make($string)`
- `validate($string, $config, $context)`
- `__construct($name)`
- `validate($string, $config, $context)`
- `validate($string, $config, $context)`
- `unpack($string)`
- `__construct()`
- `validate($string, $config, $context)`
- `validate($aIP, $config, $context)`
- `_loadRegex()`
- `validate($aIP, $config, $context)`
- `validate($string, $config, $context)`
- `transform($attr, $config, $context)`
- `transform($attr, $config, $context)`
- `transform($attr, $config, $context)`
- `__construct($attr, $css)`
- `transform($attr, $config, $context)`
- `transform($attr, $config, $context)`
- `__construct($attr, $enum_to_css, $case_sensitive = false)`
- `transform($attr, $config, $context)`
- `transform($attr, $config, $context)`
- `__construct($attr)`
- `transform($attr, $config, $context)`
- `__construct()`
- `transform($attr, $config, $context)`
- `transform($attr, $config, $context)`
- `__construct($name, $css_name = null)`
- `transform($attr, $config, $context)`
- `transform($attr, $config, $context)`
- `__construct()`
- `transform($attr, $config, $context)`
- `__construct()`
- `transform($attr, $config, $context)`
- `transform($attr, $config, $context)`
- `transform($attr, $config, $context)`
- `__construct()`
- `transform($attr, $config, $context)`
- `transform($attr, $config, $context)`
- `__construct()`
- `transform($attr, $config, $context)`
- `transform($attr, $config, $context)`
- `transform($attr, $config, $context)`
- `transform($attr, $config, $context)`
- `__construct($inline, $block)`
- `validateChildren($children, $config, $context)`
- `__construct($dtd_regex)`
- `_compileRegex()`
- `validateChildren($children, $config, $context)`
- `__construct()`
- `validateChildren($children, $config, $context)`
- `validateChildren($children, $config, $context)`
- `__construct($elements)`
- `validateChildren($children, $config, $context)`
- `validateChildren($children, $config, $context)`
- `getAllowedElements($config)`
- `validateChildren($children, $config, $context)`
- `init($config)`
- `__construct()`
- `validateChildren($children, $config, $context)`
- `__construct()`
- `decorate(&$cache)`
- `copy()`
- `add($def, $config)`
- `set($def, $config)`
- `replace($def, $config)`
- `get($config)`
- `remove($config)`
- `flush($config)`
- `cleanup($config)`
- `add($def, $config)`
- `set($def, $config)`
- `replace($def, $config)`
- `remove($config)`
- `get($config)`
- `flush($config)`
- `cleanup($config)`
- `add($def, $config)`
- `set($def, $config)`
- `replace($def, $config)`
- `get($config)`
- `remove($config)`
- `flush($config)`
- `cleanup($config)`
- `generateFilePath($config)`
- `generateDirectoryPath($config)`
- `generateBaseDirectoryPath($config)`
- `_write($file, $data, $config)`
- `_prepareDir($config)`
- `_testPermissions($dir, $chmod)`
- `copy()`
- `add($def, $config)`
- `set($def, $config)`
- `replace($def, $config)`
- `get($config)`
- `copy()`
- `add($def, $config)`
- `set($def, $config)`
- `replace($def, $config)`
- `get($config)`
- `setup($config)`
- `setup($config)`
- `getChildDef($def)`
- `setup($config)`
- `setup($config)`
- `setup($config)`
- `setup($config)`
- `setup($config)`
- `setup($config)`
- `setup($config)`
- `setup($config)`
- `setup($config)`
- `setup($config)`
- `setup($config)`
- `setup($config)`
- `setup($config)`
- `setup($config)`
- `setup($config)`
- `setup($config)`
- `setup($config)`
- `setup($config)`
- `setup($config)`
- `setup($config)`
- `setup($config)`
- `setup($config)`
- `setup($config)`
- `setup($config)`
- `getFixesForLevel($level)`
- `makeFixesForLevel($fixes)`
- `populate($fixes)`
- `getFixType($name)`
- `makeFixes()`
- `makeFixes()`
- `makeFixes()`
- `makeFixes()`
- `makeFixes()`
- `getChildDef($def)`
- `makeFixes()`
- `_pStart()`
- `handleText(&$token)`
- `handleElement(&$token)`
- `_splitText($data, &$result)`
- `_isInline($token)`
- `_pLookAhead()`
- `_checkNeedsP($current)`
- `handleElement(&$token)`
- `handleEnd(&$token)`
- `handleText(&$token)`
- `prepare($config, $context)`
- `handleText(&$token)`
- `prepare($config, $context)`
- `handleElement(&$token)`
- `__construct()`
- `prepare($config, $context)`
- `handleElement(&$token)`
- `handleEnd(&$token)`
- `prepare($config, $context)`
- `handleElement(&$token)`
- `handleEnd(&$token)`
- `__construct()`
- `tokenizeHTML($html, $config, $context)`
- `tokenizeDOM($node, &$tokens, $config)`
- `getTagName($node)`
- `getData($node)`
- `createStartNode($node, &$tokens, $collect, $config)`
- `createEndNode($node, &$tokens)`
- `transformAttrToAssoc($node_map)`
- `muteErrorHandler($errno, $errstr)`
- `callbackUndoCommentSubst($matches)`
- `callbackArmorCommentEntities($matches)`
- `wrapHTML($html, $config, $context, $use_div = true)`
- `scriptCallback($matches)`
- `tokenizeHTML($html, $config, $context)`
- `substrCount($haystack, $needle, $offset, $length)`
- `parseAttributeString($string, $config, $context)`
- `__construct($data, $line = null, $col = null)`
- `toTokenPair()`
- `__construct($name, $attr = array()`
- `toTokenPair()`
- `__construct($data, $is_whitespace, $line = null, $col = null)`
- `toTokenPair()`
- `execute($tokens, $config, $context)`
- `__construct()`
- `execute($tokens, $config, $context)`
- `f($node)`
- `execute($tokens, $config, $context)`
- `processToken($token, $injector = -1)`
- `insertBefore($token)`
- `remove()`
- `execute($tokens, $config, $context)`
- `execute($tokens, $config, $context)`
- `transform($tag, $config, $context)`
- `__construct($transform_to, $style = null)`
- `transform($tag, $config, $context)`
- `__construct($data, $line = null, $col = null)`
- `toNode()`
- `__construct($name, $attr = array()`
- `toNode()`
- `toNode()`
- `toNode()`
- `__construct($data, $line = null, $col = null)`
- `toNode()`
- `prepare($config)`
- `filter(&$uri, $config, $context)`
- `filter(&$uri, $config, $context)`
- `filter(&$uri, $config, $context)`
- `prepare($config)`
- `filter(&$uri, $config, $context)`
- `prepare($config)`
- `filter(&$uri, $config, $context)`
- `_collapseStack($stack)`
- `prepare($config)`
- `filter(&$uri, $config, $context)`
- `makeReplace($uri, $config, $context)`
- `prepare($config)`
- `filter(&$uri, $config, $context)`
- `doValidate(&$uri, $config, $context)`
- `muteErrorHandler($errno, $errstr)`
- `doValidate(&$uri, $config, $context)`
- `doValidate(&$uri, $config, $context)`
- `doValidate(&$uri, $config, $context)`
- `doValidate(&$uri, $config, $context)`
- `doValidate(&$uri, $config, $context)`
- `doValidate(&$uri, $config, $context)`
- `doValidate(&$uri, $config, $context)`
- `parseImplementation($var, $type, $allow_null)`
- `parseImplementation($var, $type, $allow_null)`
- `evalExpression($expr)`
---

### 📄 cmsb/vendor/ralouphie/getallheaders/src/getallheaders.php
- `getallheaders()`
---

### 📄 cmsb/vendor/phpmailer/phpmailer/src/OAuthTokenProvider.php
- `getOauth64()`
---

### 📄 cmsb/vendor/phpmailer/phpmailer/src/DSNConfigurator.php
- `mailer($dsn, $exceptions = null)`
- `configure(PHPMailer $mailer, $dsn)`
- `parseDSN($dsn)`
- `applyConfig(PHPMailer $mailer, $config)`
- `configureSMTP($mailer, $config)`
- `configureOptions(PHPMailer $mailer, $options)`
- `parseUrl($url)`
---

### 📄 cmsb/vendor/phpmailer/phpmailer/src/PHPMailer.php
- `__construct($exceptions = null)`
- `__destruct()`
- `mailPassthru($to, $subject, $body, $header, $params)`
- `edebug($str)`
- `isHTML($isHtml = true)`
- `isSMTP()`
- `isMail()`
- `isSendmail()`
- `isQmail()`
- `addAddress($address, $name = '')`
- `addCC($address, $name = '')`
- `addBCC($address, $name = '')`
- `addReplyTo($address, $name = '')`
- `addOrEnqueueAnAddress($kind, $address, $name)`
- `setBoundaries()`
- `addAnAddress($kind, $address, $name = '')`
- `parseAddresses($addrstr, $useimap = true, $charset = self::CHARSET_ISO88591)`
- `setFrom($address, $name = '', $auto = true)`
- `getLastMessageID()`
- `validateAddress($address, $patternselect = null)`
- `idnSupported()`
- `punyencodeAddress($address)`
- `send()`
- `preSend()`
- `postSend()`
- `sendmailSend($header, $body)`
- `isShellSafe($string)`
- `isPermittedPath($path)`
- `fileIsAccessible($path)`
- `mailSend($header, $body)`
- `getSMTPInstance()`
- `setSMTPInstance(SMTP $smtp)`
- `setSMTPXclientAttribute($name, $value)`
- `getSMTPXclientAttributes()`
- `smtpSend($header, $body)`
- `smtpConnect($options = null)`
- `smtpClose()`
- `setLanguage($langcode = 'en', $lang_path = '')`
- `getTranslations()`
- `addrAppend($type, $addr)`
- `addrFormat($addr)`
- `wrapText($message, $length, $qp_mode = false)`
- `utf8CharBoundary($encodedText, $maxLength)`
- `setWordWrap()`
- `createHeader()`
- `getMailMIME()`
- `getSentMIMEMessage()`
- `generateId()`
- `createBody()`
- `getBoundaries()`
- `getBoundary($boundary, $charSet, $contentType, $encoding)`
- `endBoundary($boundary)`
- `setMessageType()`
- `headerLine($name, $value)`
- `textLine($value)`
- `addAttachment(
        $path,
        $name = '',
        $encoding = self::ENCODING_BASE64,
        $type = '',
        $disposition = 'attachment'
    )`
- `getAttachments()`
- `attachAll($disposition_type, $boundary)`
- `encodeFile($path, $encoding = self::ENCODING_BASE64)`
- `encodeString($str, $encoding = self::ENCODING_BASE64)`
- `encodeHeader($str, $position = 'text')`
- `hasMultiBytes($str)`
- `has8bitChars($text)`
- `base64EncodeWrapMB($str, $linebreak = null)`
- `encodeQP($string)`
- `encodeQ($str, $position = 'text')`
- `addStringAttachment(
        $string,
        $filename,
        $encoding = self::ENCODING_BASE64,
        $type = '',
        $disposition = 'attachment'
    )`
- `addEmbeddedImage(
        $path,
        $cid,
        $name = '',
        $encoding = self::ENCODING_BASE64,
        $type = '',
        $disposition = 'inline'
    )`
- `addStringEmbeddedImage(
        $string,
        $cid,
        $name = '',
        $encoding = self::ENCODING_BASE64,
        $type = '',
        $disposition = 'inline'
    )`
- `validateEncoding($encoding)`
- `cidExists($cid)`
- `inlineImageExists()`
- `attachmentExists()`
- `alternativeExists()`
- `clearQueuedAddresses($kind)`
- `clearAddresses()`
- `clearCCs()`
- `clearBCCs()`
- `clearReplyTos()`
- `clearAllRecipients()`
- `clearAttachments()`
- `clearCustomHeaders()`
- `clearCustomHeader($name, $value = null)`
- `replaceCustomHeader($name, $value = null)`
- `setError($msg)`
- `rfcDate()`
- `serverHostname()`
- `isValidHost($host)`
- `lang($key)`
- `getSmtpErrorMessage($base_key)`
- `isError()`
- `addCustomHeader($name, $value = null)`
- `getCustomHeaders()`
- `msgHTML($message, $basedir = '', $advanced = false)`
- `html2text($html, $advanced = false)`
- `_mime_types($ext = '')`
- `filenameToType($filename)`
- `mb_pathinfo($path, $options = null)`
- `set($name, $value = '')`
- `secureHeader($str)`
- `normalizeBreaks($text, $breaktype = null)`
- `stripTrailingWSP($text)`
- `stripTrailingBreaks($text)`
- `getLE()`
- `setLE($le)`
- `sign($cert_filename, $key_filename, $key_pass, $extracerts_filename = '')`
- `DKIM_QP($txt)`
- `DKIM_Sign($signHeader)`
- `DKIM_HeaderC($signHeader)`
- `DKIM_BodyC($body)`
- `DKIM_Add($headers_line, $subject, $body)`
- `hasLineLongerThanMax($str)`
- `quotedString($str)`
- `getToAddresses()`
- `getCcAddresses()`
- `getBccAddresses()`
- `getReplyToAddresses()`
- `getAllRecipientAddresses()`
- `doCallback($isSent, $to, $cc, $bcc, $subject, $body, $from, $extra)`
- `getOAuth()`
- `setOAuth(OAuthTokenProvider $oauth)`
---

### 📄 cmsb/vendor/phpmailer/phpmailer/src/OAuth.php
- `__construct($options)`
- `getGrant()`
- `getToken()`
- `getOauth64()`
---

### 📄 cmsb/vendor/phpmailer/phpmailer/src/SMTP.php
- `edebug($str, $level = 0)`
- `connect($host, $port = null, $timeout = 30, $options = [])`
- `getSMTPConnection($host, $port = null, $timeout = 30, $options = [])`
- `if(strpos(PHP_OS, 'WIN')`
- `startTLS()`
- `authenticate(
        $username,
        $password,
        $authtype = null,
        $OAuth = null
    )`
- `hmac($data, $key)`
- `connected()`
- `close()`
- `data($msg_data)`
- `hello($host = '')`
- `sendHello($hello, $host)`
- `parseHelloFields($type)`
- `mail($from)`
- `quit($close_on_error = true)`
- `recipient($address, $dsn = '')`
- `xclient(array $vars)`
- `reset()`
- `sendCommand($command, $commandstring, $expect)`
- `sendAndMail($from)`
- `verify($name)`
- `noop()`
- `turn()`
- `client_send($data, $command = '')`
- `getError()`
- `getServerExtList()`
- `getServerExt($name)`
- `getLastReply()`
- `get_lines()`
- `setVerp($enabled = false)`
- `getVerp()`
- `setError($message, $detail = '', $smtp_code = '', $smtp_code_ex = '')`
- `setDebugOutput($method = 'echo')`
- `getDebugOutput()`
- `setDebugLevel($level = 0)`
- `getDebugLevel()`
- `setTimeout($timeout = 0)`
- `getTimeout()`
- `errorHandler($errno, $errmsg, $errfile = '', $errline = 0)`
- `recordLastTransactionID()`
- `getLastTransactionID()`
---

### 📄 cmsb/vendor/phpmailer/phpmailer/src/Exception.php
- `errorMessage()`
---

### 📄 cmsb/vendor/phpmailer/phpmailer/src/POP3.php
- `popBeforeSmtp(
        $host,
        $port = false,
        $timeout = false,
        $username = '',
        $password = '',
        $debug_level = 0
    )`
- `authorise($host, $port = false, $timeout = false, $username = '', $password = '', $debug_level = 0)`
- `connect($host, $port = false, $tval = 30)`
- `login($username = '', $password = '')`
- `disconnect()`
- `getResponse($size = 128)`
- `sendString($string)`
- `checkResponse($string)`
- `setError($error)`
- `getErrors()`
- `catchWarning($errno, $errstr, $errfile, $errline)`
---

### 📄 cmsb/vendor/guzzlehttp/promises/src/PromiseInterface.php
- `then(
        ?callable $onFulfilled = null,
        ?callable $onRejected = null
    )`
- `otherwise(callable $onRejected)`
- `getState()`
- `resolve($value)`
- `reject($reason)`
- `cancel()`
- `wait(bool $unwrap = true)`
---

### 📄 cmsb/vendor/guzzlehttp/promises/src/TaskQueue.php
- `__construct(bool $withShutdown = true)`
- `isEmpty()`
- `add(callable $task)`
- `run()`
- `disableShutdown()`
---

### 📄 cmsb/vendor/guzzlehttp/promises/src/Each.php
- `of(
        $iterable,
        ?callable $onFulfilled = null,
        ?callable $onRejected = null
    )`
- `ofLimit(
        $iterable,
        $concurrency,
        ?callable $onFulfilled = null,
        ?callable $onRejected = null
    )`
- `ofLimitAll(
        $iterable,
        $concurrency,
        ?callable $onFulfilled = null
    )`
---

### 📄 cmsb/vendor/guzzlehttp/promises/src/Promise.php
- `__construct(
        ?callable $waitFn = null,
        ?callable $cancelFn = null
    )`
- `then(
        ?callable $onFulfilled = null,
        ?callable $onRejected = null
    )`
- `otherwise(callable $onRejected)`
- `wait(bool $unwrap = true)`
- `getState()`
- `cancel()`
- `resolve($value)`
- `reject($reason)`
- `settle(string $state, $value)`
- `callHandler(int $index, $value, array $handler)`
- `waitIfPending()`
- `invokeWaitFn()`
- `invokeWaitList()`
---

### 📄 cmsb/vendor/guzzlehttp/promises/src/PromisorInterface.php
- `promise()`
---

### 📄 cmsb/vendor/guzzlehttp/promises/src/RejectionException.php
- `__construct($reason, ?string $description = null)`
- `getReason()`
---

### 📄 cmsb/vendor/guzzlehttp/promises/src/Create.php
- `promiseFor($value)`
- `rejectionFor($reason)`
- `exceptionFor($reason)`
- `iterFor($value)`
---

### 📄 cmsb/vendor/guzzlehttp/promises/src/Coroutine.php
- `createPromise($value)`
- `__construct(callable $generatorFn)`
- `of(callable $generatorFn)`
- `then(
        ?callable $onFulfilled = null,
        ?callable $onRejected = null
    )`
- `otherwise(callable $onRejected)`
- `wait(bool $unwrap = true)`
- `getState()`
- `resolve($value)`
- `reject($reason)`
- `cancel()`
- `nextCoroutine($yielded)`
- `_handleSuccess($value)`
- `_handleFailure($reason)`
---

### 📄 cmsb/vendor/guzzlehttp/promises/src/RejectedPromise.php
- `__construct($reason)`
- `then(
        ?callable $onFulfilled = null,
        ?callable $onRejected = null
    )`
- `otherwise(callable $onRejected)`
- `wait(bool $unwrap = true)`
- `getState()`
- `resolve($value)`
- `reject($reason)`
- `cancel()`
---

### 📄 cmsb/vendor/guzzlehttp/promises/src/Is.php
- `pending(PromiseInterface $promise)`
- `settled(PromiseInterface $promise)`
- `fulfilled(PromiseInterface $promise)`
- `rejected(PromiseInterface $promise)`
---

### 📄 cmsb/vendor/guzzlehttp/promises/src/Utils.php
- `queue(?TaskQueueInterface $assign = null)`
- `task(callable $task)`
- `inspect(PromiseInterface $promise)`
- `inspectAll($promises)`
- `unwrap($promises)`
- `all($promises, bool $recursive = false)`
- `some(int $count, $promises)`
- `any($promises)`
- `settle($promises)`
---

### 📄 cmsb/vendor/guzzlehttp/promises/src/EachPromise.php
- `__construct($iterable, array $config = [])`
- `promise()`
- `createPromise()`
- `refillPending()`
- `addPending()`
- `advanceIterator()`
- `step(int $idx)`
- `checkIfFinished()`
---

### 📄 cmsb/vendor/guzzlehttp/promises/src/AggregateException.php
- `__construct(string $msg, array $reasons)`
---

### 📄 cmsb/vendor/guzzlehttp/promises/src/FulfilledPromise.php
- `__construct($value)`
- `then(
        ?callable $onFulfilled = null,
        ?callable $onRejected = null
    )`
- `otherwise(callable $onRejected)`
- `wait(bool $unwrap = true)`
- `getState()`
- `resolve($value)`
- `reject($reason)`
- `cancel()`
---

### 📄 cmsb/vendor/guzzlehttp/promises/src/TaskQueueInterface.php
- `isEmpty()`
- `add(callable $task)`
- `run()`
---

### 📄 cmsb/vendor/guzzlehttp/psr7/src/FnStream.php
- `__construct(array $methods)`
- `__get(string $name)`
- `__destruct()`
- `__wakeup()`
- `decorate(StreamInterface $stream, array $methods)`
- `__toString()`
- `close()`
- `detach()`
- `getSize()`
- `tell()`
- `eof()`
- `isSeekable()`
- `rewind()`
- `seek($offset, $whence = SEEK_SET)`
- `isWritable()`
- `write($string)`
- `isReadable()`
- `read($length)`
- `getContents()`
- `getMetadata($key = null)`
---

### 📄 cmsb/vendor/guzzlehttp/psr7/src/UriNormalizer.php
- `normalize(UriInterface $uri, int $flags = self::PRESERVING_NORMALIZATIONS)`
- `isEquivalent(UriInterface $uri1, UriInterface $uri2, int $normalizations = self::PRESERVING_NORMALIZATIONS)`
- `capitalizePercentEncoding(UriInterface $uri)`
- `decodeUnreservedCharacters(UriInterface $uri)`
- `__construct()`
---

### 📄 cmsb/vendor/guzzlehttp/psr7/src/MessageTrait.php
- `getProtocolVersion()`
- `withProtocolVersion($version)`
- `getHeaders()`
- `hasHeader($header)`
- `getHeader($header)`
- `getHeaderLine($header)`
- `withHeader($header, $value)`
- `withAddedHeader($header, $value)`
- `withoutHeader($header)`
- `getBody()`
- `withBody(StreamInterface $body)`
- `setHeaders(array $headers)`
- `normalizeHeaderValue($value)`
- `trimAndValidateHeaderValues(array $values)`
- `assertHeader($header)`
- `assertValue(string $value)`
---

### 📄 cmsb/vendor/guzzlehttp/psr7/src/MimeType.php
- `fromFilename(string $filename)`
- `fromExtension(string $extension)`
---

### 📄 cmsb/vendor/guzzlehttp/psr7/src/CachingStream.php
- `__construct(
        StreamInterface $stream,
        ?StreamInterface $target = null
    )`
- `getSize()`
- `rewind()`
- `seek($offset, $whence = SEEK_SET)`
- `read($length)`
- `write($string)`
- `eof()`
- `close()`
- `cacheEntireStream()`
---

### 📄 cmsb/vendor/guzzlehttp/psr7/src/PumpStream.php
- `__construct(callable $source, array $options = [])`
- `__toString()`
- `close()`
- `detach()`
- `getSize()`
- `tell()`
- `eof()`
- `isSeekable()`
- `rewind()`
- `seek($offset, $whence = SEEK_SET)`
- `isWritable()`
- `write($string)`
- `isReadable()`
- `read($length)`
- `getContents()`
- `getMetadata($key = null)`
- `pump(int $length)`
---

### 📄 cmsb/vendor/guzzlehttp/psr7/src/NoSeekStream.php
- `seek($offset, $whence = SEEK_SET)`
- `isSeekable()`
---

### 📄 cmsb/vendor/guzzlehttp/psr7/src/Response.php
- `__construct(
        int $status = 200,
        array $headers = [],
        $body = null,
        string $version = '1.1',
        ?string $reason = null
    )`
- `getStatusCode()`
- `getReasonPhrase()`
- `withStatus($code, $reasonPhrase = '')`
- `assertStatusCodeIsInteger($statusCode)`
- `assertStatusCodeRange(int $statusCode)`
---

### 📄 cmsb/vendor/guzzlehttp/psr7/src/InflateStream.php
- `__construct(StreamInterface $stream)`
---

### 📄 cmsb/vendor/guzzlehttp/psr7/src/StreamWrapper.php
- `getResource(StreamInterface $stream)`
- `createStreamContext(StreamInterface $stream)`
- `register()`
- `stream_open(string $path, string $mode, int $options, ?string &$opened_path = null)`
- `stream_read(int $count)`
- `stream_write(string $data)`
- `stream_tell()`
- `stream_eof()`
- `stream_seek(int $offset, int $whence)`
- `stream_cast(int $cast_as)`
- `stream_stat()`
- `url_stat(string $path, int $flags)`
---

### 📄 cmsb/vendor/guzzlehttp/psr7/src/Stream.php
- `__construct($stream, array $options = [])`
- `__destruct()`
- `__toString()`
- `getContents()`
- `close()`
- `detach()`
- `getSize()`
- `isReadable()`
- `isWritable()`
- `isSeekable()`
- `eof()`
- `tell()`
- `rewind()`
- `seek($offset, $whence = SEEK_SET)`
- `read($length)`
- `write($string)`
- `getMetadata($key = null)`
---

### 📄 cmsb/vendor/guzzlehttp/psr7/src/UriComparator.php
- `isCrossOrigin(UriInterface $original, UriInterface $modified)`
- `computePort(UriInterface $uri)`
- `__construct()`
---

### 📄 cmsb/vendor/guzzlehttp/psr7/src/Request.php
- `__construct(
        string $method,
        $uri,
        array $headers = [],
        $body = null,
        string $version = '1.1'
    )`
- `getRequestTarget()`
- `withRequestTarget($requestTarget)`
- `getMethod()`
- `withMethod($method)`
- `getUri()`
- `withUri(UriInterface $uri, $preserveHost = false)`
- `updateHostFromUri()`
- `assertMethod($method)`
---

### 📄 cmsb/vendor/guzzlehttp/psr7/src/Header.php
- `parse($header)`
- `normalize($header)`
- `splitList($values)`
---

### 📄 cmsb/vendor/guzzlehttp/psr7/src/DroppingStream.php
- `__construct(StreamInterface $stream, int $maxLength)`
- `write($string)`
---

### 📄 cmsb/vendor/guzzlehttp/psr7/src/LazyOpenStream.php
- `__construct(string $filename, string $mode)`
- `createStream()`
---

### 📄 cmsb/vendor/guzzlehttp/psr7/src/BufferStream.php
- `__construct(int $hwm = 16384)`
- `__toString()`
- `getContents()`
- `close()`
- `detach()`
- `getSize()`
- `isReadable()`
- `isWritable()`
- `isSeekable()`
- `rewind()`
- `seek($offset, $whence = SEEK_SET)`
- `eof()`
- `tell()`
- `read($length)`
- `write($string)`
- `getMetadata($key = null)`
---

### 📄 cmsb/vendor/guzzlehttp/psr7/src/HttpFactory.php
- `createUploadedFile(
        StreamInterface $stream,
        ?int $size = null,
        int $error = \UPLOAD_ERR_OK,
        ?string $clientFilename = null,
        ?string $clientMediaType = null
    )`
- `createStream(string $content = '')`
- `createStreamFromFile(string $file, string $mode = 'r')`
- `createStreamFromResource($resource)`
- `createServerRequest(string $method, $uri, array $serverParams = [])`
- `createResponse(int $code = 200, string $reasonPhrase = '')`
- `createRequest(string $method, $uri)`
- `createUri(string $uri = '')`
---

### 📄 cmsb/vendor/guzzlehttp/psr7/src/Uri.php
- `__construct(string $uri = '')`
- `parse(string $url)`
- `__toString()`
- `composeComponents(?string $scheme, ?string $authority, string $path, ?string $query, ?string $fragment)`
- `isDefaultPort(UriInterface $uri)`
- `isAbsolute(UriInterface $uri)`
- `isNetworkPathReference(UriInterface $uri)`
- `isAbsolutePathReference(UriInterface $uri)`
- `isRelativePathReference(UriInterface $uri)`
- `isSameDocumentReference(UriInterface $uri, ?UriInterface $base = null)`
- `withoutQueryValue(UriInterface $uri, string $key)`
- `withQueryValue(UriInterface $uri, string $key, ?string $value)`
- `withQueryValues(UriInterface $uri, array $keyValueArray)`
- `fromParts(array $parts)`
- `getScheme()`
- `getAuthority()`
- `getUserInfo()`
- `getHost()`
- `getPort()`
- `getPath()`
- `getQuery()`
- `getFragment()`
- `withScheme($scheme)`
- `withUserInfo($user, $password = null)`
- `withHost($host)`
- `withPort($port)`
- `withPath($path)`
- `withQuery($query)`
- `withFragment($fragment)`
- `jsonSerialize()`
- `applyParts(array $parts)`
- `filterScheme($scheme)`
- `filterUserInfoComponent($component)`
- `filterHost($host)`
- `filterPort($port)`
- `getFilteredQueryString(UriInterface $uri, array $keys)`
- `generateQueryString(string $key, ?string $value)`
- `removeDefaultPort()`
- `filterPath($path)`
- `filterQueryAndFragment($str)`
- `rawurlencodeMatchZero(array $match)`
- `validateState()`
---

### 📄 cmsb/vendor/guzzlehttp/psr7/src/StreamDecoratorTrait.php
- `__construct(StreamInterface $stream)`
- `__get(string $name)`
- `__toString()`
- `getContents()`
- `__call(string $method, array $args)`
- `close()`
- `getMetadata($key = null)`
- `detach()`
- `getSize()`
- `eof()`
- `tell()`
- `isReadable()`
- `isWritable()`
- `isSeekable()`
- `rewind()`
- `seek($offset, $whence = SEEK_SET)`
- `read($length)`
- `write($string)`
- `createStream()`
---

### 📄 cmsb/vendor/guzzlehttp/psr7/src/UploadedFile.php
- `__construct(
        $streamOrFile,
        ?int $size,
        int $errorStatus,
        ?string $clientFilename = null,
        ?string $clientMediaType = null
    )`
- `setStreamOrFile($streamOrFile)`
- `setError(int $error)`
- `isStringNotEmpty($param)`
- `isOk()`
- `isMoved()`
- `validateActive()`
- `getStream()`
- `moveTo($targetPath)`
- `getSize()`
- `getError()`
- `getClientFilename()`
- `getClientMediaType()`
---

### 📄 cmsb/vendor/guzzlehttp/psr7/src/Utils.php
- `caselessRemove(array $keys, array $data)`
- `copyToStream(StreamInterface $source, StreamInterface $dest, int $maxLen = -1)`
- `copyToString(StreamInterface $stream, int $maxLen = -1)`
- `hash(StreamInterface $stream, string $algo, bool $rawOutput = false)`
- `modifyRequest(RequestInterface $request, array $changes)`
- `readLine(StreamInterface $stream, ?int $maxLength = null)`
- `redactUserInfo(UriInterface $uri)`
- `streamFor($resource = '', array $options = [])`
- `tryFopen(string $filename, string $mode)`
- `tryGetContents($stream)`
- `uriFor($uri)`
---

### 📄 cmsb/vendor/guzzlehttp/psr7/src/Query.php
- `parse(string $str, $urlEncoding = true)`
- `build(array $params, $encoding = PHP_QUERY_RFC3986, bool $treatBoolsAsInts = true)`
---

### 📄 cmsb/vendor/guzzlehttp/psr7/src/AppendStream.php
- `__construct(array $streams = [])`
- `__toString()`
- `addStream(StreamInterface $stream)`
- `getContents()`
- `close()`
- `detach()`
- `tell()`
- `getSize()`
- `eof()`
- `rewind()`
- `seek($offset, $whence = SEEK_SET)`
- `read($length)`
- `isReadable()`
- `isWritable()`
- `isSeekable()`
- `write($string)`
- `getMetadata($key = null)`
---

### 📄 cmsb/vendor/guzzlehttp/psr7/src/UriResolver.php
- `removeDotSegments(string $path)`
- `resolve(UriInterface $base, UriInterface $rel)`
- `relativize(UriInterface $base, UriInterface $target)`
- `getRelativePath(UriInterface $base, UriInterface $target)`
- `__construct()`
---

### 📄 cmsb/vendor/guzzlehttp/psr7/src/LimitStream.php
- `__construct(
        StreamInterface $stream,
        int $limit = -1,
        int $offset = 0
    )`
- `eof()`
- `getSize()`
- `seek($offset, $whence = SEEK_SET)`
- `tell()`
- `setOffset(int $offset)`
- `setLimit(int $limit)`
- `read($length)`
---

### 📄 cmsb/vendor/guzzlehttp/psr7/src/ServerRequest.php
- `__construct(
        string $method,
        $uri,
        array $headers = [],
        $body = null,
        string $version = '1.1',
        array $serverParams = []
    )`
- `normalizeFiles(array $files)`
- `createUploadedFileFromSpec(array $value)`
- `normalizeNestedFileSpec(array $files = [])`
- `fromGlobals()`
- `extractHostAndPortFromAuthority(string $authority)`
- `getUriFromGlobals()`
- `getServerParams()`
- `getUploadedFiles()`
- `withUploadedFiles(array $uploadedFiles)`
- `getCookieParams()`
- `withCookieParams(array $cookies)`
- `getQueryParams()`
- `withQueryParams(array $query)`
- `getParsedBody()`
- `withParsedBody($data)`
- `getAttributes()`
- `getAttribute($attribute, $default = null)`
- `withAttribute($attribute, $value)`
- `withoutAttribute($attribute)`
---

### 📄 cmsb/vendor/guzzlehttp/psr7/src/Message.php
- `toString(MessageInterface $message)`
- `bodySummary(MessageInterface $message, int $truncateAt = 120)`
- `rewindBody(MessageInterface $message)`
- `parseMessage(string $message)`
- `parseRequestUri(string $path, array $headers)`
- `parseRequest(string $message)`
- `parseResponse(string $message)`
---

### 📄 cmsb/vendor/guzzlehttp/psr7/src/MultipartStream.php
- `__construct(array $elements = [], ?string $boundary = null)`
- `getBoundary()`
- `isWritable()`
- `getHeaders(array $headers)`
- `createStream(array $elements = [])`
- `addElement(AppendStream $stream, array $element)`
- `createElement(string $name, StreamInterface $stream, ?string $filename, array $headers)`
- `getHeader(array $headers, string $key)`
---

### 📄 cmsb/vendor/guzzlehttp/guzzle/src/functions.php
- `describe_type($input)`
- `headers_from_lines(iterable $lines)`
- `debug_resource($value = null)`
- `choose_handler()`
- `default_user_agent()`
- `default_ca_bundle()`
- `normalize_header_keys(array $headers)`
- `is_host_in_noproxy(string $host, array $noProxyArray)`
- `json_decode(string $json, bool $assoc = false, int $depth = 512, int $options = 0)`
- `json_encode($value, int $options = 0, int $depth = 512)`
---

### 📄 cmsb/vendor/guzzlehttp/guzzle/src/ClientTrait.php
- `request(string $method, $uri, array $options = [])`
- `get($uri, array $options = [])`
- `head($uri, array $options = [])`
- `put($uri, array $options = [])`
- `post($uri, array $options = [])`
- `patch($uri, array $options = [])`
- `delete($uri, array $options = [])`
- `requestAsync(string $method, $uri, array $options = [])`
- `getAsync($uri, array $options = [])`
- `headAsync($uri, array $options = [])`
- `putAsync($uri, array $options = [])`
- `postAsync($uri, array $options = [])`
- `patchAsync($uri, array $options = [])`
- `deleteAsync($uri, array $options = [])`
---

### 📄 cmsb/vendor/guzzlehttp/guzzle/src/RedirectMiddleware.php
- `__construct(callable $nextHandler)`
- `__invoke(RequestInterface $request, array $options)`
- `checkRedirect(RequestInterface $request, array $options, ResponseInterface $response)`
- `withTracking(PromiseInterface $promise, string $uri, int $statusCode)`
- `guardMax(RequestInterface $request, ResponseInterface $response, array &$options)`
- `modifyRequest(RequestInterface $request, array $options, ResponseInterface $response)`
- `redirectUri(
        RequestInterface $request,
        ResponseInterface $response,
        array $protocols
    )`
---

### 📄 cmsb/vendor/guzzlehttp/guzzle/src/BodySummarizer.php
- `__construct(?int $truncateAt = null)`
- `summarize(MessageInterface $message)`
---

### 📄 cmsb/vendor/guzzlehttp/guzzle/src/TransferStats.php
- `__construct(
        RequestInterface $request,
        ?ResponseInterface $response = null,
        ?float $transferTime = null,
        $handlerErrorData = null,
        array $handlerStats = []
    )`
- `getRequest()`
- `getResponse()`
- `hasResponse()`
- `getHandlerErrorData()`
- `getEffectiveUri()`
- `getTransferTime()`
- `getHandlerStats()`
- `getHandlerStat(string $stat)`
---

### 📄 cmsb/vendor/guzzlehttp/guzzle/src/Pool.php
- `__construct(ClientInterface $client, $requests, array $config = [])`
- `promise()`
- `batch(ClientInterface $client, $requests, array $options = [])`
- `cmpCallback(array &$options, string $name, array &$results)`
---

### 📄 cmsb/vendor/guzzlehttp/guzzle/src/HandlerStack.php
- `create(?callable $handler = null)`
- `__construct(?callable $handler = null)`
- `__invoke(RequestInterface $request, array $options)`
- `__toString()`
- `setHandler(callable $handler)`
- `hasHandler()`
- `unshift(callable $middleware, ?string $name = null)`
- `push(callable $middleware, string $name = '')`
- `before(string $findName, callable $middleware, string $withName = '')`
- `after(string $findName, callable $middleware, string $withName = '')`
- `remove($remove)`
- `resolve()`
- `findByName(string $name)`
- `splice(string $findName, string $withName, callable $middleware, bool $before)`
- `debugCallable($fn)`
---

### 📄 cmsb/vendor/guzzlehttp/guzzle/src/ClientInterface.php
- `send(RequestInterface $request, array $options = [])`
- `sendAsync(RequestInterface $request, array $options = [])`
- `request(string $method, $uri, array $options = [])`
- `requestAsync(string $method, $uri, array $options = [])`
- `getConfig(?string $option = null)`
---

### 📄 cmsb/vendor/guzzlehttp/guzzle/src/MessageFormatterInterface.php
- `format(RequestInterface $request, ?ResponseInterface $response = null, ?\Throwable $error = null)`
---

### 📄 cmsb/vendor/guzzlehttp/guzzle/src/PrepareBodyMiddleware.php
- `__construct(callable $nextHandler)`
- `__invoke(RequestInterface $request, array $options)`
- `addExpectHeader(RequestInterface $request, array $options, array &$modify)`
---

### 📄 cmsb/vendor/guzzlehttp/guzzle/src/Utils.php
- `describeType($input)`
- `headersFromLines(iterable $lines)`
- `debugResource($value = null)`
- `chooseHandler()`
- `defaultUserAgent()`
- `defaultCaBundle()`
- `normalizeHeaderKeys(array $headers)`
- `isHostInNoProxy(string $host, array $noProxyArray)`
- `jsonDecode(string $json, bool $assoc = false, int $depth = 512, int $options = 0)`
- `jsonEncode($value, int $options = 0, int $depth = 512)`
- `currentTime()`
- `idnUriConvert(UriInterface $uri, int $options = 0)`
- `getenv(string $name)`
- `idnToAsci(string $domain, int $options, ?array &$info = [])`
---

### 📄 cmsb/vendor/guzzlehttp/guzzle/src/Middleware.php
- `cookies()`
- `httpErrors(?BodySummarizerInterface $bodySummarizer = null)`
- `history(&$container)`
- `tap(?callable $before = null, ?callable $after = null)`
- `redirect()`
- `retry(callable $decider, ?callable $delay = null)`
- `log(LoggerInterface $logger, $formatter, string $logLevel = 'info')`
- `prepareBody()`
- `mapRequest(callable $fn)`
- `mapResponse(callable $fn)`
---

### 📄 cmsb/vendor/guzzlehttp/guzzle/src/RetryMiddleware.php
- `__construct(callable $decider, callable $nextHandler, ?callable $delay = null)`
- `exponentialDelay(int $retries)`
- `__invoke(RequestInterface $request, array $options)`
- `onFulfilled(RequestInterface $request, array $options)`
- `onRejected(RequestInterface $req, array $options)`
- `doRetry(RequestInterface $request, array $options, ?ResponseInterface $response = null)`
---

### 📄 cmsb/vendor/guzzlehttp/guzzle/src/MessageFormatter.php
- `__construct(?string $template = self::CLF)`
- `format(RequestInterface $request, ?ResponseInterface $response = null, ?\Throwable $error = null)`
- `headers(MessageInterface $message)`
---

### 📄 cmsb/vendor/guzzlehttp/guzzle/src/Client.php
- `__construct(array $config = [])`
- `__call($method, $args)`
- `sendAsync(RequestInterface $request, array $options = [])`
- `send(RequestInterface $request, array $options = [])`
- `sendRequest(RequestInterface $request)`
- `requestAsync(string $method, $uri = '', array $options = [])`
- `request(string $method, $uri = '', array $options = [])`
- `getConfig(?string $option = null)`
- `buildUri(UriInterface $uri, array $config)`
- `configureDefaults(array $config)`
- `prepareDefaults(array $options)`
- `transfer(RequestInterface $request, array $options)`
- `applyOptions(RequestInterface $request, array &$options)`
- `invalidBody()`
---

### 📄 cmsb/vendor/guzzlehttp/guzzle/src/BodySummarizerInterface.php
- `summarize(MessageInterface $message)`
---

### 📄 cmsb/vendor/guzzlehttp/guzzle/src/Handler/EasyHandle.php
- `createResponse()`
- `__get($name)`
---

### 📄 cmsb/vendor/guzzlehttp/guzzle/src/Handler/CurlFactory.php
- `__construct(int $maxHandles)`
- `create(RequestInterface $request, array $options)`
- `supportsHttp2()`
- `supportsTls12()`
- `supportsTls13()`
- `release(EasyHandle $easy)`
- `finish(callable $handler, EasyHandle $easy, CurlFactoryInterface $factory)`
- `invokeStats(EasyHandle $easy)`
- `finishError(callable $handler, EasyHandle $easy, CurlFactoryInterface $factory)`
- `getCurlVersion()`
- `createRejection(EasyHandle $easy, array $ctx)`
- `sanitizeCurlError(string $error, UriInterface $uri)`
- `getDefaultConf(EasyHandle $easy)`
- `applyMethod(EasyHandle $easy, array &$conf)`
- `applyBody(RequestInterface $request, array $options, array &$conf)`
- `applyHeaders(EasyHandle $easy, array &$conf)`
- `removeHeader(string $name, array &$options)`
- `applyHandlerOptions(EasyHandle $easy, array &$conf)`
- `retryFailedRewind(callable $handler, EasyHandle $easy, array $ctx)`
- `createHeaderFn(EasyHandle $easy)`
- `__destruct()`
---

### 📄 cmsb/vendor/guzzlehttp/guzzle/src/Handler/CurlMultiHandler.php
- `__construct(array $options = [])`
- `__get($name)`
- `__destruct()`
- `__invoke(RequestInterface $request, array $options)`
- `tick()`
- `tickInQueue()`
- `execute()`
- `addRequest(array $entry)`
- `cancel($id)`
- `processMessages()`
- `timeToNext()`
---

### 📄 cmsb/vendor/guzzlehttp/guzzle/src/Handler/CurlHandler.php
- `__construct(array $options = [])`
- `__invoke(RequestInterface $request, array $options)`
---

### 📄 cmsb/vendor/guzzlehttp/guzzle/src/Handler/MockHandler.php
- `createWithMiddleware(?array $queue = null, ?callable $onFulfilled = null, ?callable $onRejected = null)`
- `__construct(?array $queue = null, ?callable $onFulfilled = null, ?callable $onRejected = null)`
- `__invoke(RequestInterface $request, array $options)`
- `append(...$values)`
- `getLastRequest()`
- `getLastOptions()`
- `count()`
- `reset()`
- `invokeStats(
        RequestInterface $request,
        array $options,
        ?ResponseInterface $response = null,
        $reason = null
    )`
---

### 📄 cmsb/vendor/guzzlehttp/guzzle/src/Handler/Proxy.php
- `wrapSync(callable $default, callable $sync)`
- `wrapStreaming(callable $default, callable $streaming)`
---

### 📄 cmsb/vendor/guzzlehttp/guzzle/src/Handler/StreamHandler.php
- `__invoke(RequestInterface $request, array $options)`
- `invokeStats(
        array $options,
        RequestInterface $request,
        ?float $startTime,
        ?ResponseInterface $response = null,
        ?\Throwable $error = null
    )`
- `createResponse(RequestInterface $request, array $options, $stream, ?float $startTime)`
- `createSink(StreamInterface $stream, array $options)`
- `checkDecode(array $options, array $headers, $stream)`
- `drain(StreamInterface $source, StreamInterface $sink, string $contentLength)`
- `createResource(callable $callback)`
- `createStream(RequestInterface $request, array $options)`
- `resolveHost(RequestInterface $request, array $options)`
- `getDefaultContext(RequestInterface $request)`
- `add_proxy(RequestInterface $request, array &$options, $value, array &$params)`
- `parse_proxy(string $url)`
- `add_timeout(RequestInterface $request, array &$options, $value, array &$params)`
- `add_crypto_method(RequestInterface $request, array &$options, $value, array &$params)`
- `add_verify(RequestInterface $request, array &$options, $value, array &$params)`
- `add_cert(RequestInterface $request, array &$options, $value, array &$params)`
- `add_progress(RequestInterface $request, array &$options, $value, array &$params)`
- `add_debug(RequestInterface $request, array &$options, $value, array &$params)`
- `addNotification(array &$params, callable $notify)`
- `callArray(array $functions)`
---

### 📄 cmsb/vendor/guzzlehttp/guzzle/src/Handler/HeaderProcessor.php
- `parseHeaders(array $headers)`
---

### 📄 cmsb/vendor/guzzlehttp/guzzle/src/Handler/CurlFactoryInterface.php
- `create(RequestInterface $request, array $options)`
- `release(EasyHandle $easy)`
---

### 📄 cmsb/vendor/guzzlehttp/guzzle/src/Cookie/SessionCookieJar.php
- `__construct(string $sessionKey, bool $storeSessionCookies = false)`
- `__destruct()`
- `save()`
- `load()`
---

### 📄 cmsb/vendor/guzzlehttp/guzzle/src/Cookie/CookieJarInterface.php
- `withCookieHeader(RequestInterface $request)`
- `extractCookies(RequestInterface $request, ResponseInterface $response)`
- `setCookie(SetCookie $cookie)`
- `clear(?string $domain = null, ?string $path = null, ?string $name = null)`
- `clearSessionCookies()`
- `toArray()`
---

### 📄 cmsb/vendor/guzzlehttp/guzzle/src/Cookie/SetCookie.php
- `fromString(string $cookie)`
- `__construct(array $data = [])`
- `__toString()`
- `toArray()`
- `getName()`
- `setName($name)`
- `getValue()`
- `setValue($value)`
- `getDomain()`
- `setDomain($domain)`
- `getPath()`
- `setPath($path)`
- `getMaxAge()`
- `setMaxAge($maxAge)`
- `getExpires()`
- `setExpires($timestamp)`
- `getSecure()`
- `setSecure($secure)`
- `getDiscard()`
- `setDiscard($discard)`
- `getHttpOnly()`
- `setHttpOnly($httpOnly)`
- `matchesPath(string $requestPath)`
- `matchesDomain(string $domain)`
- `isExpired()`
- `validate()`
---

### 📄 cmsb/vendor/guzzlehttp/guzzle/src/Cookie/FileCookieJar.php
- `__construct(string $cookieFile, bool $storeSessionCookies = false)`
- `__destruct()`
- `save(string $filename)`
- `load(string $filename)`
---

### 📄 cmsb/vendor/guzzlehttp/guzzle/src/Cookie/CookieJar.php
- `__construct(bool $strictMode = false, array $cookieArray = [])`
- `fromArray(array $cookies, string $domain)`
- `shouldPersist(SetCookie $cookie, bool $allowSessionCookies = false)`
- `getCookieByName(string $name)`
- `toArray()`
- `clear(?string $domain = null, ?string $path = null, ?string $name = null)`
- `clearSessionCookies()`
- `setCookie(SetCookie $cookie)`
- `count()`
- `getIterator()`
- `extractCookies(RequestInterface $request, ResponseInterface $response)`
- `getCookiePathFromRequest(RequestInterface $request)`
- `withCookieHeader(RequestInterface $request)`
- `removeCookieIfEmpty(SetCookie $cookie)`
---

### 📄 cmsb/vendor/guzzlehttp/guzzle/src/Exception/BadResponseException.php
- `__construct(
        string $message,
        RequestInterface $request,
        ResponseInterface $response,
        ?\Throwable $previous = null,
        array $handlerContext = []
    )`
- `hasResponse()`
- `getResponse()`
---

### 📄 cmsb/vendor/guzzlehttp/guzzle/src/Exception/ConnectException.php
- `__construct(
        string $message,
        RequestInterface $request,
        ?\Throwable $previous = null,
        array $handlerContext = []
    )`
- `getRequest()`
- `getHandlerContext()`
---

### 📄 cmsb/vendor/guzzlehttp/guzzle/src/Exception/RequestException.php
- `__construct(
        string $message,
        RequestInterface $request,
        ?ResponseInterface $response = null,
        ?\Throwable $previous = null,
        array $handlerContext = []
    )`
- `wrapException(RequestInterface $request, \Throwable $e)`
- `create(
        RequestInterface $request,
        ?ResponseInterface $response = null,
        ?\Throwable $previous = null,
        array $handlerContext = [],
        ?BodySummarizerInterface $bodySummarizer = null
    )`
- `getRequest()`
- `getResponse()`
- `hasResponse()`
- `getHandlerContext()`
---

### 📄 cmsb/vendor/composer/ClassLoader.php
- `__construct($vendorDir = null)`
- `getPrefixes()`
- `getPrefixesPsr4()`
- `getFallbackDirs()`
- `getFallbackDirsPsr4()`
- `getClassMap()`
- `addClassMap(array $classMap)`
- `add($prefix, $paths, $prepend = false)`
- `addPsr4($prefix, $paths, $prepend = false)`
- `set($prefix, $paths)`
- `setPsr4($prefix, $paths)`
- `setUseIncludePath($useIncludePath)`
- `getUseIncludePath()`
- `setClassMapAuthoritative($classMapAuthoritative)`
- `isClassMapAuthoritative()`
- `setApcuPrefix($apcuPrefix)`
- `getApcuPrefix()`
- `register($prepend = false)`
- `unregister()`
- `loadClass($class)`
- `findFile($class)`
- `getRegisteredLoaders()`
- `findFileWithExtension($class, $ext)`
- `initializeIncludeClosure()`
---

### 📄 cmsb/vendor/composer/autoload_static.php
- `getInitializer(ClassLoader $loader)`
---

### 📄 cmsb/vendor/composer/autoload_real.php
- `loadClassLoader($class)`
- `getLoader()`
---

### 📄 cmsb/vendor/composer/InstalledVersions.php
- `getInstalledPackages()`
- `getInstalledPackagesByType($type)`
- `isInstalled($packageName, $includeDevRequirements = true)`
- `satisfies(VersionParser $parser, $packageName, $constraint)`
- `getVersionRanges($packageName)`
- `getVersion($packageName)`
- `getPrettyVersion($packageName)`
- `getReference($packageName)`
- `getInstallPath($packageName)`
- `getRootPackage()`
- `getRawData()`
- `getAllRawData()`
- `reload($data)`
- `getInstalled()`
---

### 📄 cmsb/vendor/composer/ca-bundle/src/CaBundle.php
- `getSystemCaRootBundlePath(?LoggerInterface $logger = null)`
- `getBundledCaBundlePath()`
- `validateCaFile($filename, ?LoggerInterface $logger = null)`
- `openssl_x509_parse()`
- `isOpensslParseSafe()`
- `reset()`
- `getEnvVariable($name)`
- `caFileUsable($certFile, ?LoggerInterface $logger = null)`
- `caDirUsable($certDir, ?LoggerInterface $logger = null)`
- `isFile($certFile, ?LoggerInterface $logger = null)`
- `isDir($certDir, ?LoggerInterface $logger = null)`
- `isReadable($certFileOrDir, ?LoggerInterface $logger = null)`
- `glob($pattern, ?LoggerInterface $logger = null)`
---

### 📄 cmsb/vendor/itools/smartstring/src/SmartString.php
- `__construct(string|int|float|bool|null $value)`
- `new(string|int|float|bool|null|array $value)`
- `value()`
- `rawValue(mixed $value)`
- `int()`
- `float()`
- `bool()`
- `string()`
- `jsonSerialize()`
- `__toString()`
- `htmlEncode(bool $encodeBr = false)`
- `urlEncode()`
- `jsonEncode()`
- `noEncode()`
- `textOnly()`
- `nl2br()`
- `trim(...$args)`
- `maxWords(int $max, string $ellipsis = "...")`
- `maxChars(int $max, string $ellipsis = "...")`
- `dateFormat(?string $format = null)`
- `dateTimeFormat(?string $format = null)`
- `numberFormat(?int $decimals = 0)`
- `phoneFormat()`
- `percent(int $decimals = 0)`
- `percentOf(int|float|SmartString|SmartNull $total, ?int $decimals = 0)`
- `add(int|float|SmartString $addend)`
- `subtract(int|float|SmartString|SmartNull $subtrahend)`
- `multiply(int|float|SmartString $multiplier)`
- `divide(int|float|SmartString|SmartNull $divisor)`
- `or(int|float|string|SmartString $fallback)`
- `ifNull(int|float|string|SmartString $fallback)`
- `ifBlank(int|float|string|SmartString $fallback)`
- `isZero(int|float|string|SmartString $fallback)`
- `if(string|int|float|bool|null $condition, string|int|float|bool|null|object $valueIfTrue)`
- `set(string|int|float|bool|null|object $newValue)`
- `apply(callable|string $func, mixed ...$args)`
- `help(mixed $value = null)`
- `__debugInfo()`
- `__get(string $property)`
- `__call($method, $args)`
- `__callStatic($method, $args)`
- `xmpWrap($output)`
- `logDeprecation($error)`
---

### 📄 cmsb/vendor/itools/smartarray/src/SmartNull.php
- `__construct($useSmartStrings = false)`
- `__debugInfo()`
- `help()`
- `current()`
- `next()`
- `key()`
- `valid()`
- `rewind()`
- `offsetGet($offset)`
- `offsetSet($offset, $value)`
- `offsetExists($offset)`
- `offsetUnset($offset)`
- `__get(string $name)`
- `__call($name, array $arguments)`
- `__toString()`
---

### 📄 cmsb/vendor/itools/smartarray/src/SmartArray.php
- `__construct(array $array = [], array $properties = [])`
- `new(array $array = [], array $properties = [])`
- `newSS(array $array = [], array $properties = [])`
- `get(int|string $key, mixed $default = null)`
- `first()`
- `last()`
- `nth(int $index)`
- `offsetSet(mixed $key, mixed $value)`
- `offsetGet(mixed $key)`
- `rawValue(mixed $value)`
- `isEmpty()`
- `isNotEmpty()`
- `isFirst()`
- `isLast()`
- `position()`
- `isMultipleOf(int $value)`
- `chunk(int $size)`
- `sort(int $flags = SORT_REGULAR)`
- `sortBy(string $column, int $type = SORT_REGULAR)`
- `unique()`
- `filter(?callable $callback = null)`
- `where(array $conditions)`
- `toArray()`
- `keys()`
- `values(string|int|null $key = null)`
- `indexBy(string $column, bool $asList = false)`
- `groupBy(string $column)`
- `pluck(string|int $valueColumn, ?string $keyColumn = null)`
- `pluckNth(int $index)`
- `implode(string $separator)`
- `map(callable $callback)`
- `merge(array|SmartArray ...$arrays)`
- `mysqli(?string $property = null)`
- `load(string $column)`
- `setLoadHandler(callable $customLoadHandler)`
- `root()`
- `help()`
- `debug($debugLevel = 0)`
- `prettyPrintR(mixed $var, int $debugLevel = 0, int $depth = 0, string $keyPrefix = '', string $loadComment = "")`
- `xmpWrap($output)`
- `__debugInfo()`
- `assertFlatArray()`
- `assertNestedArray()`
- `warnIfMissing(string|int $key, string $warningType)`
- `logDeprecation($error)`
- `logDeprecationAndReturn($returnOrCallback, $error)`
- `__toString()`
- `__call($method, $args)`
- `occurredInFile($addReportedFileLine = false)`
- `encodeOutput(mixed $value, string|int $key = '')`
- `newSmartNull()`
- `isFlat()`
- `isNested()`
- `getIterator()`
- `jsonSerialize()`
- `getProperty(string $name)`
- `col(string|int $key)`
---

### 📄 cmsb/vendor/league/oauth2-google/src/Provider/GoogleUser.php
- `__construct(array $response)`
- `getId()`
- `getName()`
- `getFirstName()`
- `getLastName()`
- `getLocale()`
- `getEmail()`
- `getHostedDomain()`
- `getAvatar()`
- `toArray()`
- `getResponseValue($key)`
---

### 📄 cmsb/vendor/league/oauth2-google/src/Provider/Google.php
- `getBaseAuthorizationUrl()`
- `getBaseAccessTokenUrl(array $params)`
- `getResourceOwnerDetailsUrl(AccessToken $token)`
- `getAuthorizationParameters(array $options)`
- `getDefaultScopes()`
- `getScopeSeparator()`
- `checkResponse(ResponseInterface $response, $data)`
- `createResourceOwner(array $response, AccessToken $token)`
- `assertMatchingDomain(?string $hostedDomain)`
---

### 📄 cmsb/vendor/league/oauth2-google/src/Exception/HostedDomainException.php
- `notMatchingDomain($configuredDomain)`
---

### 📄 cmsb/vendor/league/oauth2-client/src/Token/AccessToken.php
- `setTimeNow($timeNow)`
- `resetTimeNow()`
- `getTimeNow()`
- `__construct(array $options = [])`
- `isExpirationTimestamp($value)`
- `getToken()`
- `getRefreshToken()`
- `getExpires()`
- `getResourceOwnerId()`
- `hasExpired()`
- `getValues()`
- `__toString()`
- `jsonSerialize()`
---

### 📄 cmsb/vendor/league/oauth2-client/src/Token/AccessTokenInterface.php
- `getToken()`
- `getRefreshToken()`
- `getExpires()`
- `hasExpired()`
- `getValues()`
- `__toString()`
- `jsonSerialize()`
---

### 📄 cmsb/vendor/league/oauth2-client/src/Token/ResourceOwnerAccessTokenInterface.php
- `getResourceOwnerId()`
---

### 📄 cmsb/vendor/league/oauth2-client/src/OptionProvider/PostAuthOptionProvider.php
- `getAccessTokenOptions($method, array $params)`
- `getAccessTokenBody(array $params)`
---

### 📄 cmsb/vendor/league/oauth2-client/src/OptionProvider/HttpBasicAuthOptionProvider.php
- `getAccessTokenOptions($method, array $params)`
---

### 📄 cmsb/vendor/league/oauth2-client/src/OptionProvider/OptionProviderInterface.php
- `getAccessTokenOptions($method, array $params)`
---

### 📄 cmsb/vendor/league/oauth2-client/src/Provider/GenericResourceOwner.php
- `__construct(array $response, $resourceOwnerId)`
- `getId()`
- `toArray()`
---

### 📄 cmsb/vendor/league/oauth2-client/src/Provider/GenericProvider.php
- `__construct(array $options = [], array $collaborators = [])`
- `getConfigurableOptions()`
- `getRequiredOptions()`
- `assertRequiredOptions(array $options)`
- `getBaseAuthorizationUrl()`
- `getBaseAccessTokenUrl(array $params)`
- `getResourceOwnerDetailsUrl(AccessToken $token)`
- `getDefaultScopes()`
- `getAccessTokenMethod()`
- `getAccessTokenResourceOwnerId()`
- `getScopeSeparator()`
- `getPkceMethod()`
- `checkResponse(ResponseInterface $response, $data)`
- `createResourceOwner(array $response, AccessToken $token)`
---

### 📄 cmsb/vendor/league/oauth2-client/src/Provider/ResourceOwnerInterface.php
- `getId()`
- `toArray()`
---

### 📄 cmsb/vendor/league/oauth2-client/src/Provider/AbstractProvider.php
- `__construct(array $options = [], array $collaborators = [])`
- `getAllowedClientOptions(array $options)`
- `setGrantFactory(GrantFactory $factory)`
- `getGrantFactory()`
- `setRequestFactory(RequestFactory $factory)`
- `getRequestFactory()`
- `setHttpClient(HttpClientInterface $client)`
- `getHttpClient()`
- `setOptionProvider(OptionProviderInterface $provider)`
- `getOptionProvider()`
- `getState()`
- `setPkceCode($pkceCode)`
- `getPkceCode()`
- `getBaseAuthorizationUrl()`
- `getBaseAccessTokenUrl(array $params)`
- `getResourceOwnerDetailsUrl(AccessToken $token)`
- `getRandomState($length = 32)`
- `getRandomPkceCode($length = 64)`
- `getDefaultScopes()`
- `getScopeSeparator()`
- `getPkceMethod()`
- `getAuthorizationParameters(array $options)`
- `getAuthorizationQuery(array $params)`
- `getAuthorizationUrl(array $options = [])`
- `authorize(
        array $options = [],
        callable $redirectHandler = null
    )`
- `appendQuery($url, $query)`
- `getAccessTokenMethod()`
- `getAccessTokenResourceOwnerId()`
- `getAccessTokenQuery(array $params)`
- `verifyGrant($grant)`
- `getAccessTokenUrl(array $params)`
- `getAccessTokenRequest(array $params)`
- `getAccessToken($grant, array $options = [])`
- `getRequest($method, $url, array $options = [])`
- `getAuthenticatedRequest($method, $url, $token, array $options = [])`
- `createRequest($method, $url, $token, array $options)`
- `getResponse(RequestInterface $request)`
- `getParsedResponse(RequestInterface $request)`
- `parseJson($content)`
- `getContentType(ResponseInterface $response)`
- `parseResponse(ResponseInterface $response)`
- `checkResponse(ResponseInterface $response, $data)`
- `prepareAccessTokenResponse(array $result)`
- `createAccessToken(array $response, AbstractGrant $grant)`
- `createResourceOwner(array $response, AccessToken $token)`
- `getResourceOwner(AccessToken $token)`
- `fetchResourceOwnerDetails(AccessToken $token)`
- `getDefaultHeaders()`
- `getAuthorizationHeaders($token = null)`
- `getHeaders($token = null)`
---

### 📄 cmsb/vendor/league/oauth2-client/src/Provider/Exception/IdentityProviderException.php
- `__construct($message, $code, $response)`
- `getResponseBody()`
---

### 📄 cmsb/vendor/league/oauth2-client/src/Tool/BearerAuthorizationTrait.php
- `getAuthorizationHeaders($token = null)`
---

### 📄 cmsb/vendor/league/oauth2-client/src/Tool/ArrayAccessorTrait.php
- `getValueByKey(array $data, $key, $default = null)`
---

### 📄 cmsb/vendor/league/oauth2-client/src/Tool/ProviderRedirectTrait.php
- `followRequestRedirects(RequestInterface $request)`
- `getHttpClient()`
- `getRedirectLimit()`
- `isRedirect(ResponseInterface $response)`
- `getResponse(RequestInterface $request)`
- `setRedirectLimit($limit)`
---

### 📄 cmsb/vendor/league/oauth2-client/src/Tool/GuardedPropertyTrait.php
- `fillProperties(array $options = [])`
- `getGuarded()`
- `isGuarded($property)`
---

### 📄 cmsb/vendor/league/oauth2-client/src/Tool/MacAuthorizationTrait.php
- `getTokenId(AccessToken $token)`
- `getMacSignature($id, $ts, $nonce)`
- `getRandomState($length = 32)`
- `getAuthorizationHeaders($token = null)`
---

### 📄 cmsb/vendor/league/oauth2-client/src/Tool/RequestFactory.php
- `getRequest(
        $method,
        $uri,
        array $headers = [],
        $body = null,
        $version = '1.1'
    )`
- `parseOptions(array $options)`
- `getRequestWithOptions($method, $uri, array $options = [])`
---

### 📄 cmsb/vendor/league/oauth2-client/src/Tool/QueryBuilderTrait.php
- `buildQueryString(array $params)`
---

### 📄 cmsb/vendor/league/oauth2-client/src/Tool/RequiredParameterTrait.php
- `checkRequiredParameter($name, array $params)`
- `checkRequiredParameters(array $names, array $params)`
---

### 📄 cmsb/vendor/league/oauth2-client/src/Grant/AbstractGrant.php
- `getName()`
- `getRequiredRequestParameters()`
- `__toString()`
- `prepareRequestParameters(array $defaults, array $options)`
---

### 📄 cmsb/vendor/league/oauth2-client/src/Grant/RefreshToken.php
- `getName()`
- `getRequiredRequestParameters()`
---

### 📄 cmsb/vendor/league/oauth2-client/src/Grant/AuthorizationCode.php
- `getName()`
- `getRequiredRequestParameters()`
---

### 📄 cmsb/vendor/league/oauth2-client/src/Grant/Password.php
- `getName()`
- `getRequiredRequestParameters()`
---

### 📄 cmsb/vendor/league/oauth2-client/src/Grant/GrantFactory.php
- `setGrant($name, AbstractGrant $grant)`
- `getGrant($name)`
- `registerDefaultGrant($name)`
- `isGrant($class)`
- `checkGrant($class)`
---

### 📄 cmsb/vendor/league/oauth2-client/src/Grant/ClientCredentials.php
- `getName()`
- `getRequiredRequestParameters()`
---

### 📄 cmsb/vendor/firebase/php-jwt/src/BeforeValidException.php
- `setPayload(object $payload)`
- `getPayload()`
---

### 📄 cmsb/vendor/firebase/php-jwt/src/CachedKeySet.php
- `__construct(
        string $jwksUri,
        ClientInterface $httpClient,
        RequestFactoryInterface $httpFactory,
        CacheItemPoolInterface $cache,
        ?int $expiresAfter = null,
        bool $rateLimit = false,
        ?string $defaultAlg = null
    )`
- `offsetGet($keyId)`
- `offsetExists($keyId)`
- `offsetSet($offset, $value)`
- `offsetUnset($offset)`
- `formatJwksForCache(string $jwks)`
- `keyIdExists(string $keyId)`
- `rateLimitExceeded()`
- `getCacheItem()`
- `setCacheKeys()`
---

### 📄 cmsb/vendor/firebase/php-jwt/src/Key.php
- `__construct(
        $keyMaterial,
        string $algorithm
    )`
- `getAlgorithm()`
- `getKeyMaterial()`
---

### 📄 cmsb/vendor/firebase/php-jwt/src/JWK.php
- `parseKeySet(array $jwks, ?string $defaultAlg = null)`
- `parseKey(array $jwk, ?string $defaultAlg = null)`
- `createPemFromCrvAndXYCoordinates(string $crv, string $x, string $y)`
- `createPemFromModulusAndExponent(
        string $n,
        string $e
    )`
- `encodeLength(int $length)`
- `encodeDER(int $type, string $value)`
- `encodeOID(string $oid)`
---

### 📄 cmsb/vendor/firebase/php-jwt/src/JWTExceptionWithPayloadInterface.php
- `getPayload()`
- `setPayload(object $payload)`
---

### 📄 cmsb/vendor/firebase/php-jwt/src/ExpiredException.php
- `setPayload(object $payload)`
- `getPayload()`
---

### 📄 cmsb/vendor/firebase/php-jwt/src/JWT.php
- `decode(
        string $jwt,
        $keyOrKeyArray,
        ?stdClass &$headers = null
    )`
- `encode(
        array $payload,
        $key,
        string $alg,
        ?string $keyId = null,
        ?array $head = null
    )`
- `sign(
        string $msg,
        $key,
        string $alg
    )`
- `verify(
        string $msg,
        string $signature,
        $keyMaterial,
        string $alg
    )`
- `jsonDecode(string $input)`
- `jsonEncode(array $input)`
- `urlsafeB64Decode(string $input)`
- `convertBase64UrlToBase64(string $input)`
- `urlsafeB64Encode(string $input)`
- `getKey(
        $keyOrKeyArray,
        ?string $kid
    )`
- `constantTimeEquals(string $left, string $right)`
- `handleJsonError(int $errno)`
- `safeStrlen(string $str)`
- `signatureToDER(string $sig)`
- `encodeDER(int $type, string $value)`
- `signatureFromDER(string $der, int $keySize)`
- `readDER(string $der, int $offset = 0)`
---

### 📄 cmsb/vendor/psr/http-message/src/ServerRequestInterface.php
- `getServerParams()`
- `getCookieParams()`
- `withCookieParams(array $cookies)`
- `getQueryParams()`
- `withQueryParams(array $query)`
- `getUploadedFiles()`
- `withUploadedFiles(array $uploadedFiles)`
- `getParsedBody()`
- `withParsedBody($data)`
- `getAttributes()`
- `getAttribute(string $name, $default = null)`
- `withAttribute(string $name, $value)`
- `withoutAttribute(string $name)`
---

### 📄 cmsb/vendor/psr/http-message/src/UriInterface.php
- `getScheme()`
- `getAuthority()`
- `getUserInfo()`
- `getHost()`
- `getPort()`
- `getPath()`
- `getQuery()`
- `getFragment()`
- `withScheme(string $scheme)`
- `withUserInfo(string $user, ?string $password = null)`
- `withHost(string $host)`
- `withPort(?int $port)`
- `withPath(string $path)`
- `withQuery(string $query)`
- `withFragment(string $fragment)`
- `__toString()`
---

### 📄 cmsb/vendor/psr/http-message/src/StreamInterface.php
- `__toString()`
- `close()`
- `detach()`
- `getSize()`
- `tell()`
- `eof()`
- `isSeekable()`
- `seek(int $offset, int $whence = SEEK_SET)`
- `rewind()`
- `isWritable()`
- `write(string $string)`
- `isReadable()`
- `read(int $length)`
- `getContents()`
- `getMetadata(?string $key = null)`
---

### 📄 cmsb/vendor/psr/http-message/src/UploadedFileInterface.php
- `getStream()`
- `moveTo(string $targetPath)`
- `getSize()`
- `getError()`
- `getClientFilename()`
- `getClientMediaType()`
---

### 📄 cmsb/vendor/psr/http-message/src/RequestInterface.php
- `getRequestTarget()`
- `withRequestTarget(string $requestTarget)`
- `getMethod()`
- `withMethod(string $method)`
- `getUri()`
- `withUri(UriInterface $uri, bool $preserveHost = false)`
---

### 📄 cmsb/vendor/psr/http-message/src/ResponseInterface.php
- `getStatusCode()`
- `withStatus(int $code, string $reasonPhrase = '')`
- `getReasonPhrase()`
---

### 📄 cmsb/vendor/psr/http-message/src/MessageInterface.php
- `getProtocolVersion()`
- `withProtocolVersion(string $version)`
- `getHeaders()`
- `hasHeader(string $name)`
- `getHeader(string $name)`
- `getHeaderLine(string $name)`
- `withHeader(string $name, $value)`
- `withAddedHeader(string $name, $value)`
- `withoutHeader(string $name)`
- `getBody()`
- `withBody(StreamInterface $body)`
---

### 📄 cmsb/vendor/psr/http-client/src/NetworkExceptionInterface.php
- `getRequest()`
---

### 📄 cmsb/vendor/psr/http-client/src/RequestExceptionInterface.php
- `getRequest()`
---

### 📄 cmsb/vendor/psr/http-client/src/ClientInterface.php
- `sendRequest(RequestInterface $request)`
---

### 📄 cmsb/vendor/psr/http-factory/src/ResponseFactoryInterface.php
- `createResponse(int $code = 200, string $reasonPhrase = '')`
---

### 📄 cmsb/vendor/psr/http-factory/src/StreamFactoryInterface.php
- `createStream(string $content = '')`
- `createStreamFromFile(string $filename, string $mode = 'r')`
- `createStreamFromResource($resource)`
---

### 📄 cmsb/vendor/psr/http-factory/src/UploadedFileFactoryInterface.php
- `createUploadedFile(
        StreamInterface $stream,
        ?int $size = null,
        int $error = \UPLOAD_ERR_OK,
        ?string $clientFilename = null,
        ?string $clientMediaType = null
    )`
---

### 📄 cmsb/vendor/psr/http-factory/src/UriFactoryInterface.php
- `createUri(string $uri = '')`
---

### 📄 cmsb/vendor/psr/http-factory/src/ServerRequestFactoryInterface.php
- `createServerRequest(string $method, $uri, array $serverParams = [])`
---

### 📄 cmsb/vendor/psr/http-factory/src/RequestFactoryInterface.php
- `createRequest(string $method, $uri)`
---

### 📄 cmsb/vendor/symfony/polyfill-php81/bootstrap.php
- `array_is_list(array $array)`
- `enum_exists(string $enum, bool $autoload = true)`
---

### 📄 cmsb/vendor/symfony/polyfill-php81/Php81.php
- `array_is_list(array $array)`
---

### 📄 cmsb/vendor/symfony/polyfill-php81/Resources/stubs/ReturnTypeWillChange.php
- `__construct()`
---

### 📄 cmsb/vendor/symfony/polyfill-php81/Resources/stubs/CURLStringFile.php
- `__construct(string $data, string $postname, string $mime = 'application/octet-stream')`
- `__set(string $name, $value)`
- `__isset(string $name)`
---

### 📄 cmsb/vendor/symfony/polyfill-php83/bootstrap81.php
- `ldap_exop_sync(\LDAP\Connection $ldap, string $request_oid, ?string $request_data = null, ?array $controls = null, &$response_data = null, &$response_oid = null)`
- `ldap_connect_wallet(?string $uri, string $wallet, #[\SensitiveParameter] string $password, int $auth_mode = \GSLC_SSL_NO_AUTH)`
---

### 📄 cmsb/vendor/symfony/polyfill-php83/bootstrap.php
- `json_validate(string $json, int $depth = 512, int $flags = 0)`
- `mb_str_pad(string $string, int $length, string $pad_string = ' ', int $pad_type = STR_PAD_RIGHT, ?string $encoding = null)`
- `stream_context_set_options($context, array $options)`
- `str_increment(string $string)`
- `str_decrement(string $string)`
- `ldap_exop_sync($ldap, string $request_oid, ?string $request_data = null, ?array $controls = null, &$response_data = null, &$response_oid = null)`
- `ldap_connect_wallet(?string $uri, string $wallet, string $password, int $auth_mode = \GSLC_SSL_NO_AUTH)`
---

### 📄 cmsb/vendor/symfony/polyfill-php83/Php83.php
- `json_validate(string $json, int $depth = 512, int $flags = 0)`
- `mb_str_pad(string $string, int $length, string $pad_string = ' ', int $pad_type = \STR_PAD_RIGHT, ?string $encoding = null)`
- `str_increment(string $string)`
- `str_decrement(string $string)`
---

### 📄 cmsb/vendor/symfony/polyfill-php83/Resources/stubs/Override.php
- `__construct()`
---

### 📄 cmsb/vendor/symfony/polyfill-php84/bootstrap.php
- `array_find(array $array, callable $callback)`
- `array_find_key(array $array, callable $callback)`
- `array_any(array $array, callable $callback)`
- `array_all(array $array, callable $callback)`
- `mb_ucfirst($string, ?string $encoding = null)`
- `mb_lcfirst($string, ?string $encoding = null)`
- `mb_trim(string $string, ?string $characters = null, ?string $encoding = null)`
- `mb_ltrim(string $string, ?string $characters = null, ?string $encoding = null)`
- `mb_rtrim(string $string, ?string $characters = null, ?string $encoding = null)`
---

### 📄 cmsb/vendor/symfony/polyfill-php84/Php84.php
- `mb_ucfirst(string $string, ?string $encoding = null)`
- `mb_lcfirst(string $string, ?string $encoding = null)`
- `array_find(array $array, callable $callback)`
- `array_find_key(array $array, callable $callback)`
- `array_any(array $array, callable $callback)`
- `array_all(array $array, callable $callback)`
- `mb_trim(string $string, ?string $characters = null, ?string $encoding = null)`
- `mb_ltrim(string $string, ?string $characters = null, ?string $encoding = null)`
- `mb_rtrim(string $string, ?string $characters = null, ?string $encoding = null)`
- `mb_internal_trim(string $regex, string $string, ?string $characters, ?string $encoding, string $function)`
---

### 📄 cmsb/vendor/symfony/polyfill-php84/Resources/stubs/Deprecated.php
- `__construct(?string $message = null, ?string $since = null)`
---

### 📄 cmsb/vendor/symfony/polyfill-php82/bootstrap.php
- `odbc_connection_string_is_quoted(string $str)`
- `odbc_connection_string_should_quote(string $str)`
- `odbc_connection_string_quote(string $str)`
- `ini_parse_quantity(string $shorthand)`
---

### 📄 cmsb/vendor/symfony/polyfill-php82/SensitiveParameterValue.php
- `__construct($value)`
- `getValue()`
- `__debugInfo()`
- `__sleep()`
- `__wakeup()`
---

### 📄 cmsb/vendor/symfony/polyfill-php82/Php82.php
- `odbc_connection_string_is_quoted(string $str)`
- `odbc_connection_string_should_quote(string $str)`
- `odbc_connection_string_quote(string $str)`
- `ini_parse_quantity(string $value)`
- `escapeString(string $string)`
---

### 📄 cmsb/vendor/symfony/polyfill-php82/NoDynamicProperties.php
- `__set(string $name, $value)`
---

### 📄 cmsb/vendor/symfony/polyfill-php82/Resources/stubs/AllowDynamicProperties.php
- `__construct()`
---

### 📄 cmsb/vendor/symfony/polyfill-php82/Resources/stubs/SensitiveParameter.php
- `__construct()`
---

### 📄 cmsb/vendor/symfony/polyfill-php82/Resources/stubs/Random/Engine.php
- `generate()`
---

### 📄 cmsb/vendor/symfony/polyfill-php82/Random/Engine/Secure.php
- `generate()`
- `__sleep()`
- `__wakeup()`
- `__clone()`
---

### 📄 cmsb/vendor/symfony/deprecation-contracts/function.php
- `trigger_deprecation(string $package, string $version, string $message, mixed ...$args)`
---
