# Sample knowledge base (in reality, this should be more extensive)
def detect_sql_injection(query, line_number)
  sql_keywords = %w(SELECT INSERT UPDATE DELETE DROP UNION OR EXEC TRUNCATE)
  suspicious_characters = [';', '--', '/*', '*/']

  query = query.upcase.gsub(/\s+/, '')

  if sql_keywords.any? { |keyword| query.include?(keyword) } ||
     suspicious_characters.any? { |char| query.include?(char) }
    return "SQL Injection detected on line #{line_number}"
  end

  false
end

def detect_xss(code, line_number)
  xss_patterns = [
    /<script.*?>.*?<\/script>/mi,
    /<\s*img.*src=["'][^"']*["'][^>]*>/i,
    /<\s*a[^>]*href=["'][^"']*["'][^>]*>/i
  ]

  if xss_patterns.any? { |pattern| code =~ pattern }
    return "XSS (Cross-Site Scripting) detected on line #{line_number}"
  end

  false
end

def detect_csrf(code)
  csrf_patterns = [
    /csrf_meta_tags/,
    /protect_from_forgery/,
    /form_authenticity_token/,
    /request\.referer/,
    /"authenticity_token" => session\[:_csrf_token\]/
  ]

  if csrf_patterns.any? { |pattern| code =~ pattern }
    return true
  end

  false
end

def detect_broken_authentication(code)
  authentication_patterns = [
    /def\s+authenticate_user/,
    /user\.authenticate/,
    /params\[:user_id\]/,
    /current_user/,
    /session\[:user_id\]/
  ]

  if authentication_patterns.any? { |pattern| code =~ pattern }
    return true
  end

  false
end

def detect_ssrf(code)
  ssrf_patterns = [
    /Net::HTTP.get/,
    /open-uri/,
    /HTTParty\.get/,
    /Faraday\.get/
    # Add more relevant patterns for SSRF detection
  ]

  if ssrf_patterns.any? { |pattern| code =~ pattern }
    return true
  end

  false
end

def detect_vulnerabilities(code, knowledge_base)
  vulnerabilities = []

  code_lines = code.split("\n")

  code_lines.each_with_index do |line, line_number|
    knowledge_base.each do |vulnerability, pattern|
      if line.match?(pattern)
        vulnerabilities << "#{vulnerability} detected on line #{line_number + 1}"
      end
    end

    vulnerabilities << detect_sql_injection(line, line_number) if detect_sql_injection(line, line_number)
    vulnerabilities << detect_xss(line, line_number) if detect_xss(line, line_number)
    vulnerabilities << detect_csrf(line) if detect_csrf(line)
    vulnerabilities << detect_broken_authentication(line) if detect_broken_authentication(line)
    vulnerabilities << detect_ssrf(line) if detect_ssrf(line)
  end

  vulnerabilities
end

def recommend_mitigations(vulnerabilities)
  mitigations = []

  vulnerabilities.each do |vulnerability|
    case vulnerability
    when "SQL Injection"
      mitigations << "Use parameterized queries or prepared statements."
    when "XSS (Cross-Site Scripting)"
      mitigations << "Sanitize user input and use output encoding."
    when "CSRF (Cross-Site Request Forgery)"
      mitigations << "Implement CSRF protection mechanisms, such as authenticity tokens."
    when "Broken Authentication"
      mitigations << "Strengthen authentication mechanisms, including password policies and session management."
    when "SSRF (Server-Side Request Forgery)"
      mitigations << "Validate and sanitize user input when making external requests."
    end
  end

  mitigations
end

def main
  knowledge_base = {
    "SQL Injection" => /SELECT\s+\*|DROP\s+TABLE|UNION|INSERT|UPDATE|DELETE|ALTER/i,
    "XSS (Cross-Site Scripting)" => /<script|<img.*src=|<a.*href=|onerror=/i,
    "CSRF (Cross-Site Request Forgery)" => /csrf_meta_tags|protect_from_forgery|form_authenticity_token/i,
    "Broken Authentication" => /def\s+authenticate_user|user\.authenticate|params\[:user_id\]|current_user|session\[:user_id\]/,
    "SSRF (Server-Side Request Forgery)" => /Net::HTTP\.get|open-uri|HTTParty\.get|Faraday\.get/i
  }

  if ARGV.empty?
    puts "Usage: ruby vulnerability_detector.rb <file.rb>"
    exit(1)
  end

  file_path = ARGV[0]

  unless File.file?(file_path)
    puts "File not found: #{file_path}"
    exit(1)
  end

  source_code = File.read(file_path)
  detected_vulnerabilities = detect_vulnerabilities(source_code, knowledge_base)

  if detected_vulnerabilities.empty?
    puts "No vulnerabilities detected."
  else
    puts "Detected vulnerabilities:"
    detected_vulnerabilities.each { |vulnerability| puts "- #{vulnerability}" }

    # Generate a report
    report_file = File.open("vulnerability_report.txt", "w")
    report_file.puts("Vulnerability Report:")
    detected_vulnerabilities.each { |vulnerability| report_file.puts("- #{vulnerability}") }
    report_file.close
    puts "Report saved to vulnerability_report.txt"
  end
end

if __FILE__ == $0
  main
end
