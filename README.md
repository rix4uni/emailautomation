## Email Automation Tool

A powerful Go-based tool for automating bug bounty report emails. This tool processes markdown files, extracts target domains, finds email addresses, and sends beautifully formatted HTML emails to recipients.

## Features

- **Multi-file Processing**: Process single markdown files or entire directories
- **Parallel Processing**: Process multiple files concurrently with intelligent rate limiting (NEW!)
- **Automatic Email Extraction**: Automatically finds email addresses from target domains using `emailextractor`
- **Domain Filtering**: Filter emails to only include those matching the base domain (optional)
- **Smart Rate Limiting**: Token bucket algorithm ensures compliance with AWS SES limits (14 emails/sec)
- **Duplicate Prevention**: Tracks sent emails using content hashing to prevent duplicate sends
- **Config-based Credentials**: Secure credential management via YAML configuration files
- **Multiple SMTP Providers**: Support for Gmail and AWS SES SMTP servers
- **HTML Email Formatting**: Beautiful markdown-to-HTML conversion with syntax highlighting
- **Debug Mode**: Save email messages to file for inspection
- **Multiple Credential Profiles**: Support for multiple email accounts via credential IDs
- **Email Verification**: Optional filtering using `emailverify` tool to ensure recipient validity
- **Thread-Safe**: Concurrent processing with mutex-protected shared resources

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
wget https://github.com/rix4uni/emailautomation/releases/download/v0.0.5/emailautomation-linux-amd64-0.0.5.tgz
tar -xvzf emailautomation-linux-amd64-0.0.5.tgz
rm -rf emailautomation-linux-amd64-0.0.5.tgz
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

  - id: "3"
    email: "bugbounty@example.com"
    app_password: "your-ses-smtp-password"
    smtp_host: "email-smtp.region.amazonaws.com"
    smtp_port: "587"
    smtp_username: "AKIAIOSFODNN7EXAMPLE"
    subject: "Bug Bounty Report: Unauthenticated Remote Code Execution via CVE-2025-55182"
```

### Configuration Fields

- **id**: Unique identifier for the credential profile
- **email**: Sender email address
- **app_password**: SMTP password (Gmail app password or AWS SES SMTP password)
- **smtp_host**: SMTP server hostname
- **smtp_port**: SMTP server port (typically 587 for TLS)
- **smtp_username**: (Optional) SMTP username. Required for AWS SES, defaults to email address if not provided (for Gmail)
- **subject**: Email subject line

### Gmail App Password Setup

1. Enable 2-Step Verification on your Google Account
2. Go to [Google App Passwords](https://myaccount.google.com/apppasswords)
3. Generate an app password for "Mail"
4. Use this password in the `app_password` field (not your regular Gmail password)
5. Do not set `smtp_username` for Gmail (it defaults to the email address)

### AWS SES SMTP Setup

AWS Simple Email Service (SES) provides SMTP credentials that allow you to send emails through their infrastructure. Follow these steps to set up AWS SES SMTP:

#### Step 1: Access AWS SES Console

1. Log in to your [AWS Console](https://console.aws.amazon.com/)
2. Navigate to **Simple Email Service (SES)**
3. Select your desired AWS region (e.g., `eu-north-1`, `us-east-1`)
4. Go to the **SMTP Settings** page:
   - Direct link: [AWS SES SMTP Settings](https://eu-north-1.console.aws.amazon.com/ses/home?region=eu-north-1#/smtp)
   - Or navigate: SES Dashboard → SMTP Settings (in the left sidebar)

#### Step 2: Create SMTP Credentials

1. On the SMTP Settings page, click **Create SMTP credentials**
2. You'll be prompted to create an IAM user for SMTP access
3. Enter a name for your IAM user (e.g., `smtp-email-sender`)
4. Click **Create**
5. **Important**: Download and save the SMTP credentials immediately:
   - The SMTP username (IAM Access Key ID) - starts with `AKIA...`
   - The SMTP password - shown only once, cannot be retrieved later
   - If you lose the password, you'll need to create new credentials

#### Step 3: Verify Your Email Address or Domain

Before sending emails, you must verify your sender email address or domain:

1. In SES Console, go to **Verified identities**
2. Click **Create identity**
3. Choose **Email address** or **Domain**
4. For email: Enter your email and click **Create identity**, then verify via the confirmation email
5. For domain: Follow DNS verification steps (recommended for production)

#### Step 4: Configure Your config.yaml

Use the credentials you created in your `config.yaml`:

```yaml
credentials:
  - id: "3"
    email: "bugbounty@yourdomain.com"  # Must be verified in SES
    app_password: "your-smtp-password"  # From Step 2
    smtp_host: "email-smtp.eu-north-1.amazonaws.com"  # Match your region
    smtp_port: "587"  # Use 587 for TLS or 465 for SSL
    smtp_username: "AKIAIOSFODNN7EXAMPLE"  # From Step 2
    subject: "Bug Bounty Report: Unauthenticated Remote Code Execution via CVE-2025-55182"
```

**SMTP Endpoints by Region:**
- `eu-north-1`: `email-smtp.eu-north-1.amazonaws.com`
- `us-east-1`: `email-smtp.us-east-1.amazonaws.com`
- `us-west-2`: `email-smtp.us-west-2.amazonaws.com`
- `eu-west-1`: `email-smtp.eu-west-1.amazonaws.com`
- For other regions, check [AWS SES SMTP Endpoints](https://docs.aws.amazon.com/ses/latest/dg/smtp-endpoints.html)

#### Step 5: SES Sandbox Mode

**Important**: New AWS SES accounts start in **sandbox mode**, which means:
- You can only send emails to verified email addresses
- You cannot send emails to unverified recipients
- Daily sending limit is 200 emails

**To move out of sandbox mode:**
1. Go to SES Console → **Account dashboard**
2. Click **Request production access**
3. Fill out the request form explaining your use case
4. Wait for AWS approval (usually 24-48 hours)

**Alternative**: For testing, verify recipient email addresses in SES Console → Verified identities

#### Step 6: Test Your Configuration

Test your AWS SES setup:

```bash
emailautomation --id 3 --markdown-file test.md --debug
```

Check the `email_debug.txt` file to verify the email format, then check your inbox (if recipient is verified) or spam folder.

#### Troubleshooting AWS SES

- **"Invalid credentials"**: Verify `smtp_username` and `app_password` are correct
- **"Email address not verified"**: Verify sender email in SES Console
- **"Recipient not verified"**: Either verify recipient email or request production access
- **"Rate limit exceeded"**: Check your SES sending limits in Account dashboard
- **"Connection timeout"**: Verify `smtp_host` matches your AWS region

#### AWS SES Optimization: High-Speed Parallel Sending

AWS SES can send emails **up to 4200x faster** than Gmail when using parallel mode. For optimal performance with AWS SES, use parallel processing:

```bash
emailautomation --domain-filter --emailverify --markdown-file mdfile --id 3 --parallel 10
```

**Why these flags for AWS SES?**

- **`--domain-filter`**: Filters emails to only include recipients matching the base domain, ensuring higher deliverability and relevance
- **`--emailverify`**: Only sends to recipients where `emailverify` returns `checked_count == 3`, ensuring valid and verified email addresses
- **`--parallel 10`**: Process 10 files concurrently with automatic rate limiting (14 emails/sec)
  - **Gmail**: 500 emails/day limit → use sequential mode only
  - **AWS SES**: Up to 50,000+ emails/day (depending on account limits) → use parallel mode
- **`--id 3`**: Uses AWS SES credential profile (adjust to match your AWS SES credential ID)

**Performance Comparison:**

| Provider | Mode | Workers | Rate Limit | Emails/Hour | Time for 1000 emails |
|----------|------|---------|------------|-------------|---------------------|
| Gmail | Sequential | 1 | 300s delay | ~12 | ~83 hours |
| AWS SES | Sequential | 1 | 1s delay | ~3,600 | ~17 minutes |
| AWS SES | Parallel | 10 | 14/sec | ~50,400 | ~1.2 minutes |

**Important Notes:**

- Only use `--parallel > 1` with AWS SES, not with Gmail (will hit rate limits)
- Always use `--domain-filter` and `--emailverify` for better deliverability and to avoid spam
- Rate limiting is automatic in parallel mode (ignores `--delay` flag)
- Check your AWS SES sending limits in the SES Console → Account dashboard
- If you're still in sandbox mode, you're limited to 200 emails/day regardless of settings

### Multiple Credential Profiles

You can define multiple credential profiles in `config.yaml` and select which one to use with the `--id` flag. This is useful for:
- Using different email accounts
- Different SMTP servers (Gmail, AWS SES, etc.)
- Different email subjects
- Mixing Gmail and AWS SES accounts

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
| `--parallel` | int | `1` | Number of parallel workers to process files concurrently (default: 1 for sequential) |
| `--delay` | int | `300` | Delay in seconds between email sends (default: 300 for Gmail's 500/day limit, ignored when --parallel > 1) |
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

#### AWS SES High-Speed Sending (Parallel Mode)

Optimized command for AWS SES with parallel processing to maximize throughput:

```bash
emailautomation --domain-filter --emailverify --markdown-file mdfile --id 3 --parallel 10
```

This configuration uses:
- `--domain-filter`: Only send to emails matching the base domain
- `--emailverify`: Only send to verified email addresses (checked_count == 3)
- `--parallel 10`: Process 10 files concurrently with smart rate limiting (14 emails/sec)
- `--id 3`: AWS SES credential profile

**Performance with Parallel Mode:**

| Mode | Workers | Rate Limit | Throughput |
|------|---------|------------|------------|
| Sequential | 1 | 300s delay | ~12 emails/hour |
| Sequential (AWS SES) | 1 | 1s delay | ~3,600 emails/hour |
| Parallel (AWS SES) | 10 | 14/sec global | ~50,400 emails/hour |

**Note**: 
- Use `--parallel` with AWS SES to fully utilize its capacity (50k emails/24hr)
- The `--delay` flag is ignored when `--parallel > 1` (rate limiting is automatic)
- For Gmail, use `--delay 300` without parallel mode to comply with 500 emails/day limit

#### Parallel Processing Examples

Process 10 files concurrently (recommended for AWS SES):

```bash
emailautomation --markdown-file reports --id 3 --parallel 10 --domain-filter --emailverify
```

Process 50 files concurrently for maximum throughput:

```bash
emailautomation --markdown-file reports --id 3 --parallel 50 --domain-filter --emailverify
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

### Sequential Mode (default, --parallel 1)
1. **File Processing**: Reads markdown files from the specified location
2. **Domain Extraction**: Extracts the target domain from the "## Target" section
3. **Email Discovery**: Uses `emailextractor` to find email addresses from the domain and subdomains
4. **Domain Filtering** (optional): Filters emails to match the base domain using `tldinfo`
5. **Duplicate Check**: Checks if the file has already been sent (using content hash)
6. **Email Composition**: Converts markdown to HTML with syntax highlighting
7. **Email Sending**: Sends email to all recipients (visible to each other)
8. **Delay**: Waits specified delay before processing next file
9. **Logging**: Records sent emails in `sent_emails.log` to prevent duplicates

### Parallel Mode (--parallel > 1)
1. **File Processing**: Reads all markdown files from the specified location
2. **Worker Pool**: Creates N worker goroutines based on `--parallel` value
3. **Job Distribution**: Distributes files to workers via channel
4. **Rate Limiting**: Each worker acquires token from global rate limiter (14/sec for AWS SES)
5. **Concurrent Processing**: Workers process files concurrently:
   - Domain extraction
   - Email discovery
   - Domain filtering (optional)
   - Duplicate check (thread-safe)
   - Email composition
   - Email sending
6. **Result Collection**: Aggregates results from all workers
7. **Thread-Safe Logging**: Records sent emails with mutex protection

**Key Differences:**
- Parallel mode ignores `--delay` flag (uses rate limiting instead)
- Thread-safe access to shared resources (sentMap, console output)
- Much higher throughput for AWS SES (up to 50k emails/24hr)

## File Structure

```yaml
emailautomation/
├── emailautomation    # Main application
├── config.yaml           # Configuration file (can be in ~/.config/emailautomation/)
├── go.mod                # Go dependencies
├── go.sum                # Go dependency checksums
├── sent_emails.log       # Log of sent emails (auto-generated)
├── email_debug.txt       # Debug email output (when using --debug)
├── skippedemails/        # Directory for skipped reports (auto-generated)
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
- File is copied to `skippedemails/` directory (with a unique suffix)
- Processing continues with next file
- Not treated as an error

The same `skippedemails/` directory is also used when:
- `--domain-filter` removes all recipients
- `--emailverify` removes all recipients

### Already Sent

If a file has already been sent (same content hash):
- File is skipped with message: `[filename] Already sent (skipping)`
- Processing continues with next file

## Parallel Processing & Rate Limits

### Gmail Rate Limits (Sequential Mode Only)

Gmail allows **500 emails per 24 hours**. Use sequential mode with delay:

```bash
emailautomation --id 1 --delay 300 --markdown-file reports
```

- 24 hours = 86,400 seconds
- 86,400 ÷ 500 = 172.8 seconds minimum
- Default: 300 seconds provides a safety margin
- **Do not use parallel mode with Gmail** (will hit rate limits)

### AWS SES with Parallel Processing (Recommended)

AWS SES supports **much higher throughput** with parallel processing:

```bash
emailautomation --id 3 --parallel 10 --domain-filter --emailverify --markdown-file reports
```

**AWS SES Limits:**
- Up to 50,000 emails per 24 hours (depending on account)
- 14 emails per second (enforced by rate limiter)
- Parallel mode automatically manages rate limiting

**Performance Comparison:**

| Provider | Mode | Workers | Throughput | Time for 1000 emails |
|----------|------|---------|------------|---------------------|
| Gmail | Sequential | 1 | 12/hour | ~83 hours |
| AWS SES | Sequential | 1 | 3,600/hour | ~17 minutes |
| AWS SES | Parallel | 10 | 50,400/hour | ~1.2 minutes |
| AWS SES | Parallel | 50 | 50,400/hour | ~1.2 minutes |

**💡 Recommendation**: Use `--parallel 10` to `--parallel 50` with AWS SES for optimal throughput while maintaining safety margins.

### Choosing the Right Mode

**For Gmail (Sequential Mode Only):**
```bash
# Conservative (10 minutes between emails)
emailautomation --delay 600

# Aggressive (2 minutes between emails) - may hit rate limits
emailautomation --delay 120

# Default (5 minutes) - recommended
emailautomation --delay 300
```

**For AWS SES (Parallel Mode Recommended):**
```bash
# Optimal: 10 workers with automatic rate limiting
emailautomation --id 3 --parallel 10 --domain-filter --emailverify

# Maximum throughput: 50 workers
emailautomation --id 3 --parallel 50 --domain-filter --emailverify

# Sequential mode (if needed): 1-second delay
emailautomation --id 3 --delay 1 --domain-filter --emailverify
```

## Troubleshooting

### "config.yaml not found"

**Solution**: Create `config.yaml` in either:
- `~/.config/emailautomation/config.yaml` (recommended)
- `./config.yaml` (current directory)

### "535 5.7.8 Username and Password not accepted"

**Solution**: 
- For Gmail:
  - Verify your Gmail app password is correct
  - Ensure 2-Step Verification is enabled
  - Check that you're using an app password, not your regular password
  - Verify the email address matches the account
- For AWS SES:
  - Verify your SMTP username and password are correct
  - Ensure `smtp_username` is set in config.yaml
  - Check that your SES account is not in sandbox mode (or recipient is verified)
  - Verify the SMTP endpoint region matches your SES configuration

### "No emails found"

**Solution**:
- Ensure `emailextractor` is installed and in PATH
- Check that the domain in the markdown file is correct
- Verify the domain is accessible
- Check `skippedemails/` directory for skipped reports

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
