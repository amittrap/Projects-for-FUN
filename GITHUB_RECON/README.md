In the updated version of my script, I focused on building an actual secret-leak detector rather than a simple GitHub search tool.

How it works:

It uses the GitHub Code Search API to find code and config files related to a target keyword or domain (e.g., cashify, cashify.in, user@cashify.in, cashify.com, godaddy, etc.).

For each matched file, it fetches the full file contents using the GitHub contents API and scans them line-by-line.

It only considers lines that are related to the target (line text or file path contains the keyword), and then checks whether the line looks like a leaked secret.

Types of leaks detected (match_type):

password – lines containing password-like keys (e.g., password, passwd, pwd, admin_password, db_password) together with an assignment (= or :), such as:

Password: Ged545725

DB_PASSWORD = "Cashify@123"

token – lines that contain token/auth-related keywords (e.g., token, auth_token, access_token, api_token, authorization, bearer) and a non-trivial assigned value, or JWT-style tokens. For example:

Authorization: sso-key $GODADDY_KEY:$GODADDY_SECRET

ACCESS_TOKEN = "cashify-prod-XYZ123..."

sql_credentials – lines that look like database connection details or credentials, e.g.:

jdbc:mysql://user:pass@host:3306/dbname

DB_USER=cashify_user, DB_PASSWORD=Passw0rd!, DB_HOST=10.0.0.3

ip_address – lines that contain private/internal IPs in a config/assignment context:

Only flags IPs in 10.x.x.x, 172.16–31.x.x, 192.168.x.x ranges

Requires = or : in the line (e.g., auth_host = 192.168.1.1)

This intentionally ignores public DNS/IP data like zone files (e.g., 37.209.192.2 in godaddy.txt), which are not treated as leaks.

private_key – lines containing private key markers such as BEGIN PRIVATE KEY, RSA PRIVATE KEY, OPENSSH PRIVATE KEY, etc.

other – secret-like configuration values that don’t fall into the above categories but still look sensitive, for example:

ENCRYPTION_KEY = "cashify-encryption-key-987654"

GODADDY_SECRET='your_secret_here'

APP_SECRET, CLIENT_SECRET, HMAC_KEY, SMTP_USER, SMTP_PASS, etc.

Output format (per leak):
For every detected leaked line, the script records:

repo_full_name – repository in owner/repo format

file_path and file_type – file path and its extension

line_number – exact line where the leak appears

leaked_value – the full leaked line, including the sensitive value

match_type – one of password, token, sql_credentials, ip_address, private_key, or other

html_url – direct GitHub URL pointing to that exact line (with #L<line_number>)

searched_keyword – the original keyword/domain used

timestamp – ISO8601 timestamp when the scan was run

To reduce noise, the script also:

Only scans files returned by the GitHub Code Search API for the given keyword/target.

De-duplicates identical leaks (same repo, file, line content, and type).

Restricts IP leaks to internal/private IPs in config-style lines instead of flagging all public IPs or DNS rec