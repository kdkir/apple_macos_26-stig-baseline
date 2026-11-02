control 'SV-277108' do
  title 'The macOS system must disable Trivial File Transfer Protocol (TFTP) service.'
  desc 'If the system does not require TFTP support, it is nonessential and must be disabled.

The information system must be configured to provide only essential capabilities. Disabling TFTP helps prevent the unauthorized connection of devices and unauthorized transfer of information.

Note: TFTP service is disabled at startup by default.

'
  desc 'check', %q(Verify the macOS system is configured to disable TFTP service with the following command:

result="FAIL"
  enabled=$(/bin/launchctl print-disabled system | /usr/bin/grep '"com.apple.tftpd" => enabled')
  running=$(/bin/launchctl print system/com.apple.tftpd 2>/dev/null)
  
  if [[ -z "$running" ]] && [[ -z "$enabled" ]]; then
    result="PASS"
  elif [[ -n "$running" ]]; then
    result=result+" RUNNING"
  elif [[ -n "$enabled" ]]; then
    result=result+" ENABLED"
  fi
  echo $result

If the result is not "PASS", this is a finding.)
  desc 'fix', 'Configure the macOS system to disable TFTP service with the following commands:

/bin/launchctl bootout system/com.apple.tftpd 
/bin/launchctl disable system/com.apple.tftpd

The system may need a restart for the update to take effect.'
  impact 0.7
  tag check_id: 'C-81263r1149379_chk'
  tag severity: 'high'
  tag gid: 'V-277108'
  tag rid: 'SV-277108r1149417_rule'
  tag stig_id: 'APPL-26-002038'
  tag gtitle: 'SRG-OS-000074-GPOS-00042'
  tag fix_id: 'F-81168r1149380_fix'
  tag satisfies: ['SRG-OS-000074-GPOS-00042', 'SRG-OS-000080-GPOS-00048']
  tag 'documentable'
  tag cci: ['CCI-000197', 'CCI-000213']
  tag nist: ['IA-5 (1) (c)', 'AC-3']

  describe macos_launchd_service('com.apple.tftpd') do
    it { should_not be_loaded }
    it { should_not be_enabled }
  end
end
