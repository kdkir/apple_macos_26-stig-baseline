control 'SV-277089' do
  title 'The macOS system must disable Unix-to-Unix Copy Protocol (UUCP) service.'
  desc 'The system must not have the UUCP service active.

UUCP, a set of programs that enables sending files between different Unix systems and sending commands to be executed on another system, is not essential and must be disabled to prevent unauthorized connection of devices, transfer of information, and tunneling.

Note: UUCP service is disabled at startup by default with macOS.'
  desc 'check', %q(Verify the macOS system is configured to disable UUCP service with the following command:

  result="FAIL"
  enabled=$(/bin/launchctl print-disabled system | /usr/bin/grep '"com.apple.uucp" => enabled')
  running=$(/bin/launchctl print system/com.apple.uucp 2>/dev/null)
  
  if [[ -z "$running" ]] && [[ -z "$enabled" ]]; then
    result="PASS"
  elif [[ -n "$running" ]]; then
    result=result+" RUNNING"
  elif [[ -n "$enabled" ]]; then
    result=result+" ENABLED"
  fi
  echo $result

If the result is not "PASS", this is a finding.)
  desc 'fix', 'Configure the macOS system to disable UUCP service with the following command:

/bin/launchctl bootout system/com.apple.uucp
/bin/launchctl disable system/com.apple.uucp

The system may need a restart for the update to take effect.'
  impact 0.5
  tag check_id: 'C-81244r1149324_chk'
  tag severity: 'medium'
  tag gid: 'V-277089'
  tag rid: 'SV-277089r1268226_rule'
  tag stig_id: 'APPL-26-002006'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-81149r1149325_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']

  describe macos_launchd_service('com.apple.uucp') do
    it { should_not be_loaded }
    it { should_not be_enabled }
  end
end
