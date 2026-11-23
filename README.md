# Antivirus Tool

A Java Swing desktop application that scans files for malware, quarantines suspicious files, and lets you delete or restore them. Every scan is logged to a local log file and a MySQL database.

> **Educational project.** This tool uses hash matching and simple heuristics. It is not a replacement for a real antivirus product.

## Features

- **Scanning:** full or custom (choose a folder or file) scans
- **Detection:**
  - Hash matching against a list of known malicious MD5, SHA-1 and SHA-256 hashes
  - Heuristics based on suspicious file extensions such as `.exe`, `.dll`, `.scr`, `.bat`, `.vbs`, `.ps1`, `.jar` and Office macro files
- **Quarantine manager:** moves flagged files to a hidden quarantine folder and gives them a `.quarantine` extension
- **Delete or restore:** permanently delete a quarantined file, or restore it to its original location
- **Logging:** a recent log, a master log, and scan history in MySQL
- **Settings:** options for the scanner, the quarantine and the application
- **File handling:** saves settings and scan information to disk

## Project Structure

```
Antivirus-tool/
├── Home.java / .form              # Welcome screen
├── MainPage.java / .form          # Main menu
├── Scanner.java / .form           # Scanning logic and UI
├── QuarantineManager.java / .form # Quarantine, delete and restore
├── Log.java / .form               # Log viewer
├── SettingsPage.java / .form      # Settings
├── FileManager.java / .form       # File handling
├── DatabaseHelper.java            # MySQL connection (JDBC)
├── antivirus_db.sql               # Database schema and sample data
├── Icons/                         # UI images
└── logs/                          # Recent Log.txt and Master Log.txt
```

## Requirements

- JDK 17 or later
- NetBeans or IntelliJ IDEA
- MySQL or MariaDB (for example through XAMPP)
- [MySQL Connector/J](https://dev.mysql.com/downloads/connector/j/) added to the project libraries

## Setup

1. **Open the project** in NetBeans or IntelliJ.
2. **Create the database.** Import `antivirus_db.sql` into MySQL (for example with phpMyAdmin). This creates the `antivirus_db` database with the `file_scan_results` and `scan_logs` tables.
3. **Set the credentials.** In `DatabaseHelper.java`, check the connection settings (defaults: `jdbc:mysql://localhost:3306/antivirus_db`, user `root`, empty password) and change them to match your setup.
4. **Add the MySQL driver.** Add Connector/J to the project libraries.
5. **Add a hash list.** The scanner reads known-bad hashes from `malicious_hashes.txt` in the project root. This file is not in the repo. Without it the scanner prints a warning and uses heuristics only.
6. **Build and run** `Home.java`.

## Usage

1. Open the application and press **Enter**.
2. Go to **Scanner** and choose **Full** or **Custom**.
3. Go to **Quarantine Zone** and choose what to do with each file in the blacklist: delete or restore.

> **Warning:** Use a custom scan on a dummy folder with test files, not your whole computer. Heuristics can flag legitimate files such as `.jar`, `.js` or `.zip` files, and quarantining them could break programs.

## Dependencies

- JDK 17+
- Java Swing
- MySQL Connector/J

## Contributors

This was a group assignment by:

- Zaid Schaefer
- Monde Mjacu
- Imtiyaaz Hartley
- Tshikani Mafanele
- Mohau Chokoe

## License

No license has been specified yet. Consider adding one, such as MIT.

