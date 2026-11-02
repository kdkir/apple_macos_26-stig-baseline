control 'SV-277091' do
  title 'The macOS system must disable the built-in web server.'
  desc 'The built-in web server managed by launchd is a nonessential service built into macOS and must be disabled and not running.

Note: The built-in web server is disabled at startup by default with macOS.'
  desc 'check', %q(Verify the macOS system is configured to disable the built-in web server with the following command:

result="FAIL"
  enabled=$(/bin/launchctl print-disabled system | /usr/bin/grep '"org.apache.httpd" => enabled')
  running=$(/bin/launchctl print system/org.apache.httpd 2>/dev/null)
  
  if [[ -z "$running" ]] && [[ -z "$enabled" ]]; then
    result="PASS"
  elif [[ -n "$running" ]]; then
    result=result+" RUNNING"
  elif [[ -n "$enabled" ]]; then
    result=result+" ENABLED"
  fi
  echo $result

If the result is not "PASS", this is a finding.)
  desc 'fix', 'Configure the macOS system to disable the built-in web server with the following command:

/usr/sbin/apachectl stop 2>/dev/null
/bin/launchctl disable system/org.apache.httpd

The system may need a restart for the update to take effect.'
  impact 0.5
  tag check_id: 'C-81246r1149384_chk'
  tag severity: 'medium'
  tag gid: 'V-277091'
  tag rid: 'SV-277091r1268226_rule'
  tag stig_id: 'APPL-26-002008'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-81151r1149385_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']

  describe macos_launchd_service('org.apache.httpd') do
    it { should_not be_loaded }
    it { should_not be_enabled }
  end
end
