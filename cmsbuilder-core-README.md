# 📌 cmsBuilder Core Files

This repository contains the **core files of cmsBuilder**, a lightweight CMS framework. Below is a categorized breakdown of important system files and their functions.

---

## 🏗 **Core System Files**
| File Name                 | Description |
|---------------------------|-------------|
| `index.php`               | Main entry point for cmsBuilder. |
| `admin.php`               | Loads the admin dashboard. |
| `api.php`                 | Provides API endpoints for external integrations. |
| `cron.php`                | Handles scheduled tasks and background jobs. |
| `php.ini`                 | PHP configuration file for CMS settings. |
| `.htaccess`               | Web server rules for security and URL rewriting. |
| `data_folder.php.example` | Example configuration for data storage. |

---

## 📂 **Library Functions (`lib/`)**
| File Name                    | Description |
|------------------------------|-------------|
| `schema_functions.php`       | Handles database schema creation and updates. |
| `media_functions.php`        | Manages image and file uploads. |
| `errorlog_functions.php`     | Logs errors and debugging messages. |
| `pluginUI_functions.php`     | Provides UI components for plugins. |
| `login_functions.php`        | Handles user login, logout, and session management. |
| `database_functions.php`     | Contains database query helper functions. |
| `security_functions.php`     | Handles data sanitization and security enforcement. |
| `auditlog_functions.php`     | Records admin actions for auditing and security. |
| `admin_functions.php`        | Provides admin-related utility functions. |
| `forgotPassword_functions.php` | Manages password recovery and reset processes. |
| `mail_functions.php`         | Handles email sending and notifications. |
| `viewer_functions_old.php`   | Deprecated version of viewer-related functions. |

---

## 🔌 **Plugins (`plugins/`)**
| Plugin Name                   | Description |
|--------------------------------|-------------|
| `developerConsole.php`        | Developer debugging tools and logs. |
| `_example_plugin.php`         | Template file for creating a custom plugin. |
| `_example_cron.php`           | Sample cron job for scheduled tasks. |
| `offlineMode/offlineMode.php` | Provides offline mode functionality. |

---

## 📦 **Uploads & Static Files (`uploads/`)**
| File Name                     | Description |
|--------------------------------|-------------|
| `uploads/`                    | Stores user-uploaded media files. |
| `uploads/thumb/`              | Auto-generated thumbnails. |
| `uploads/thumb2/`, `thumb3/`, `thumb4/` | Different sizes of generated thumbnails. |
| `index.html` (inside folders) | Placeholder to prevent directory listing. |

---

## **📌 Notes & Best Practices**
- Avoid modifying **core library files** (`lib/`) directly. Instead, use **plugins** to extend functionality.
- Keep **database-related functions** inside `database_functions.php`.
- For security, **never expose `admin.php` publicly**—restrict access via `.htaccess`.

---

## 🚀 **How to Extend cmsBuilder**
1. **Use Plugins**: Create a new file in `plugins/` to add custom functionality.
2. **Use Hooks**: Hook into cmsBuilder’s API instead of modifying core files.
3. **Use `admin_functions.php`** for admin-related custom functions.
4. **Use `viewer_functions.php`** for customizing frontend displays.

---

## 📞 **Need Help?**
For troubleshooting or customizations, refer to:
- Official cmsBuilder Documentation
- Admin Panel Debugging (`developerConsole.php` plugin)
- Error Logs (`errorlog_functions.php`)

---

🚀 **This README was auto-generated based on actual files extracted from cmsBuilder.** If you need modifications, update this document accordingly.
