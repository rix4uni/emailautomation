## Email Automation Tool

A powerful Go-based tool for automating bug bounty report emails. This tool processes markdown files, extracts target domains, finds email addresses, and sends beautifully formatted HTML emails to recipients.

## Features

- **Multi-file Processing**: Process single markdown files or entire directories
- **Automatic Email Extraction**: Automatically finds email addresses from target domains using `emailextractor`
- **Domain Filtering**: Filter emails to only include those matching the base domain (optional)
- **Rate Limiting**: Built-in delay between emails to comply with Gmail's 500 emails/day limit
- **Duplicate Prevention**: Tracks sent emails using content hashing to prevent duplicate sends
- **Config-based Credentials**: Secure credential management via YAML configuration files
- **HTML Email Formatting**: Beautiful markdown-to-HTML conversion with syntax highlighting
- **Debug Mode**: Save email messages to file for inspection
- **Multiple Credential Profiles**: Support for multiple email accounts via credential IDs

### Prerequisites
- **emailextractor**: Required for email extraction from domains
  ```
  go install github.com/rix4uni/emailextractor@latest
  ```
- **tldinfo**: Required for domain filtering (optional, only if using `--domain-filter`)
  ```
  pipx install --force git+https://github.com/rix4uni/tldinfo.git
  ```
- **emailverify**: Required for recipient verification (optional, only if using `--emailverify`). Must be available in your `PATH`.

## Installation
```
go install github.com/rix4uni/emailautomation@latest
```

## Download prebuilt binaries
```
wget https://github.com/rix4uni/emailautomation/releases/download/v0.0.2/emailautomation-linux-amd64-0.0.2.tgz
tar -xvzf emailautomation-linux-amd64-0.0.2.tgz
rm -rf emailautomation-linux-amd64-0.0.2.tgz
mv emailautomation ~/go/bin/emailautomation
```
Or download [binary release](https://github.com/rix4uni/emailautomation/releases) for your platform.

## Compile from source
```
git clone --depth 1 github.com/rix4uni/emailautomation.git
cd emailautomation; go install
```

## Configuration

### Config File Locations

The tool checks for `config.yaml` in the following order (first found is used):

1. **Home Directory**: `~/.config/emailautomation/config.yaml` (priority)
2. **Current Directory**: `./config.yaml` (fallback)

If neither exists, the program will exit with an error.

### Config File Structure

Create a `config.yaml` file with the following structure:

```yaml
credentials:
  - id: "1"
    email: "your-email@gmail.com"
    app_password: "your-app-password"
    smtp_host: "smtp.gmail.com"
    smtp_port: "587"
    subject: "Bug Bounty Report: Unauthenticated Remote Code Execution via CVE-2025-55182"

  - id: "2"
    email: "another-email@gmail.com"
    app_password: "another-app-password"
    smtp_host: "smtp.gmail.com"
    smtp_port: "587"
    subject: "Bug Bounty Report: Unauthenticated Remote Code Execution via CVE-2025-55182"
```

### Gmail App Password Setup

1. Enable 2-Step Verification on your Google Account
2. Go to [Google App Passwords](https://myaccount.google.com/apppasswords)
3. Generate an app password for "Mail"
4. Use this password in the `app_password` field (not your regular Gmail password)

### Multiple Credential Profiles

You can define multiple credential profiles in `config.yaml` and select which one to use with the `--id` flag. This is useful for:
- Using different email accounts
- Different SMTP servers
- Different email subjects

## Usage

### Basic Usage

```yaml
# Process all markdown files in the default 'mdfile' directory
emailautomation

# Process a specific markdown file
emailautomation --markdown-file report.md

# Process all files in a directory
emailautomation --markdown-file /path/to/reports
```

### Command-Line Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--markdown-file` | string | `mdfile` | Path to a single .md file or directory containing .md files |
| `--id` | string | `1` | Credential ID to use from config.yaml |
| `--domain-filter` | bool | `false` | Filter emails to only include those matching the base domain |
| `--emailverify` | bool | `false` | Only send to recipients where `emailverify --json` returns `checked_count == 3` |
| `--delay` | int | `300` | Delay in seconds between email sends (default: 300 for Gmail's 500/day limit) |
| `--debug` | bool | `false` | Write email message to email_debug.txt for debugging |
| `--nomarkdown` | bool | `false` | Send email as plain text instead of HTML |
| `--silent` | bool | `false` | Silent mode |
| `--version` | bool | `false` | Print the version of the tool and exit |

### Examples

#### Single File Processing

```yaml
emailautomation --markdown-file report.md
```

#### Directory Processing

```yaml
emailautomation --markdown-file /path/to/reports
```

#### Using Different Credential Profile

```yaml
emailautomation --id 2
```

#### Domain Filtering

Only send emails to addresses matching the base domain:

```yaml
emailautomation --domain-filter
```

#### Custom Delay

Set a custom delay between emails (in seconds):

```yaml
# Wait 10 minutes (600 seconds) between emails
emailautomation --delay 600

# No delay (not recommended for Gmail)
emailautomation --delay 0
```

#### Debug Mode

Save the email message to `email_debug.txt` for inspection:

```yaml
emailautomation --debug
```

#### Plain Text Mode

Send emails as plain text instead of HTML:

```yaml
emailautomation --nomarkdown
```

#### Combined Flags

```yaml
emailautomation --markdown-file reports --id 2 --domain-filter --delay 300 --debug
```

## Markdown File Format

Your markdown files should follow this structure:

```markdown
## Target
```
https://example.com
```

## Commands Executed
```
  • command1
  • command2
```

## Vulnerability Summary
CVE: CVE-2025-XXXXX
Type: Remote Code Execution
...

## Exploitation Details
...
```

### Key Requirements

- **Target Section**: Must contain `## Target` heading followed by a code block with the target URL
- The tool extracts the domain from the URL in the Target section
- The rest of the markdown content becomes the email body

## How It Works

1. **File Processing**: Reads markdown files from the specified location
2. **Domain Extraction**: Extracts the target domain from the "## Target" section
3. **Email Discovery**: Uses `emailextractor` to find email addresses from the domain and subdomains
4. **Domain Filtering** (optional): Filters emails to match the base domain using `tldinfo`
5. **Duplicate Check**: Checks if the file has already been sent (using content hash)
6. **Email Composition**: Converts markdown to HTML with syntax highlighting
7. **Email Sending**: Sends email to all recipients (visible to each other)
8. **Logging**: Records sent emails in `sent_emails.log` to prevent duplicates

## File Structure

```yaml
emailautomation/
├── emailautomation    # Main application
├── config.yaml           # Configuration file (can be in ~/.config/emailautomation/)
├── go.mod                # Go dependencies
├── go.sum                # Go dependency checksums
├── sent_emails.log       # Log of sent emails (auto-generated)
├── email_debug.txt       # Debug email output (when using --debug)
├── emailnotfound/        # Directory for files with no emails found (auto-generated)
└── mdfile/               # Default directory for markdown files
    ├── 1.md
    ├── 2.md
    └── ...
```

## Log Files

### sent_emails.log

Tracks successfully sent emails to prevent duplicates:
- Format: `filepath|hash` (one entry per line)
- Uses SHA256 hash of file content
- Modified files will be sent again (new hash)

### email_debug.txt

Created when using `--debug` flag:
- Contains the complete email message (headers + body)
- Useful for troubleshooting email formatting issues

## Error Handling

### Invalid Credentials

If credentials are invalid, the program will:
- Exit immediately with error code 1
- Display: "Fatal error: invalid credentials in config.yaml"
- Show helpful message to check credentials

### No Emails Found

If no emails are found for a domain:
- File is copied to `emailnotfound/` directory
- Processing continues with next file
- Not treated as an error

### Already Sent

If a file has already been sent (same content hash):
- File is skipped with message: `[filename] Already sent (skipping)`
- Processing continues with next file

## Gmail Rate Limits

Gmail allows **500 emails per 24 hours**. The default delay of 300 seconds (5 minutes) between emails ensures compliance:

- 24 hours = 86,400 seconds
- 86,400 ÷ 500 = 172.8 seconds minimum
- Default: 300 seconds provides a safety margin

### Adjusting Delay

```yaml
# Conservative (10 minutes between emails)
emailautomation --delay 600

# Aggressive (2 minutes between emails) - may hit rate limits
emailautomation --delay 120

# No delay - NOT recommended for Gmail
emailautomation --delay 0
```

## Troubleshooting

### "config.yaml not found"

**Solution**: Create `config.yaml` in either:
- `~/.config/emailautomation/config.yaml` (recommended)
- `./config.yaml` (current directory)

### "535 5.7.8 Username and Password not accepted"

**Solution**: 
- Verify your Gmail app password is correct
- Ensure 2-Step Verification is enabled
- Check that you're using an app password, not your regular password
- Verify the email address matches the account

### "No emails found"

**Solution**:
- Ensure `emailextractor` is installed and in PATH
- Check that the domain in the markdown file is correct
- Verify the domain is accessible
- Check `emailnotfound/` directory for files with no emails

### "Failed to extract base domain"

**Solution**:
- Ensure `tldinfo` is installed and in PATH (only needed for `--domain-filter`)
- Verify the URL in the Target section is valid

### Emails going to spam

**Solution**:
- The tool includes proper email headers (Date, Message-ID, Reply-To, X-Mailer)
- Uses multipart/alternative MIME structure (HTML + plain text)
- Proper quoted-printable encoding
- If still going to spam, check recipient's spam settings

### Duplicate emails being sent

**Solution**:
- Check `sent_emails.log` to see if file is recorded
- Verify file content hasn't changed (hash would be different)
- Delete `sent_emails.log` to reset (not recommended)

## Security Notes

- **Never commit `config.yaml`** to version control
- Store credentials securely
- Use app passwords, not regular passwords
- Consider using environment variables for sensitive data (future feature)
