require 'net/http'
require 'uri'
require 'json'

# Vulnerability 1: SQL Injection
# This method is vulnerable to SQL injection because user input is directly inserted into an SQL query.
def fetch_user_data(user_id)
  query = "SELECT * FROM users WHERE id = #{user_id};"  # Dangerous interpolation of user input
  result = execute_sql(query)
  return result
end

# Vulnerability 2: Command Injection
# User input is used directly in a system command, making it possible for an attacker to execute arbitrary commands.
def run_system_command(user_input)
  system("echo #{user_input}")  # Potential command injection vulnerability
end

# Vulnerability 3: Insecure Direct Object Reference (IDOR)
# An attacker can manipulate the file path to access sensitive files they shouldn't be able to access.
def read_file(file_name)
  file = File.open("/var/www/uploads/#{file_name}", "r")  # Sensitive file access
  content = file.read
  file.close
  return content
end

# Vulnerability 4: Sensitive Data Exposure
# Sensitive data like passwords are hardcoded, which is a major security risk.
def store_password
  password = "password123"  # Hardcoded password, vulnerable to exposure
  # Store password in database...
end

# Vulnerability 5: Cross-Site Scripting (XSS)
# This method doesn't sanitize user input before displaying it, leading to potential XSS attacks.
def display_user_input(user_input)
  puts "User input: #{user_input}"  # Vulnerable to XSS if the input contains malicious HTML/JS
end

# Vulnerability 6: Insecure Deserialization
# An attacker could send a serialized object with malicious code.
def deserialize_user_data(serialized_data)
  user_data = Marshal.load(serialized_data)  # Deserialization without validation is dangerous
  return user_data
end

# Vulnerability 7: Inadequate Logging
# Log sensitive information such as passwords, which should never be logged.
def log_sensitive_info
  username = "admin"
  password = "password123"
  puts "Logging sensitive info: Username: #{username}, Password: #{password}"  # Insecure logging
end

# Vulnerability 8: Insufficient Rate Limiting
# No rate limiting on API requests, which could lead to a DoS (Denial of Service) attack.
def api_request_handler
  loop do
    # Handling user requests without any rate limiting
    puts "Processing request..."
    # Process API requests
  end
end

# Vulnerability 9: Cross-Site Request Forgery (CSRF)
# No CSRF token verification, making it vulnerable to CSRF attacks.
def process_transfer_request(user_id, amount)
  # Without CSRF protection, an attacker could forge a request on behalf of an authenticated user
  puts "Transferring $#{amount} for user #{user_id}"
  # Perform the transfer...
end

# Vulnerability 10: Unencrypted Sensitive Data Transmission
# Sending sensitive data (like credit card info) over HTTP, which can be intercepted by attackers.
def send_credit_card_data(card_number)
  uri = URI('http://example.com/submit_card')
  response = Net::HTTP.post_form(uri, 'card_number' => card_number)  # Unencrypted transmission over HTTP
  return response.body
end

# Simulating SQL execution
def execute_sql(query)
  puts "Executing SQL: #{query}"  # Simulating SQL execution
  # Actual database interaction would happen here...
end
