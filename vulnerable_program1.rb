# SQL Injection Example
user_input_sql = "SELECT * FROM users WHERE username = 'admin' AND password = ''; DROP TABLE users; --"

# XSS Example
user_input_xss = "<script>alert('XSS');</script>"

# CSRF Example
user_input_csrf = "<form action='https://example.com/attack' method='POST'><input type='hidden' name='data' value='malicious_data'></form>"

# Broken Authentication Example
def login(username, password)
  if username == "admin" && password == "password"
    return "Logged in as admin"
  else
    return "Login failed"
  end
end

# Usage of examples
puts "SQL Injection Example: #{user_input_sql}"
puts "XSS Example: #{user_input_xss}"
puts "CSRF Example: #{user_input_csrf}"
puts "Broken Authentication Example: #{login('admin', 'password')}"

