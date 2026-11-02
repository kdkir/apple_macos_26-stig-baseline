control 'SV-277085' do
  title 'The macOS system must disable Server Message Block (SMB) sharing.'
  desc 'Support for SMB file sharing is nonessential and must be disabled.

The information system must be configured to provide only essential capabilities. Enabling any service increases the attack surface for an intruder. By disabling unnecessary services, the attack surface is minimized.'
  desc 'check', %q(Verify the macOS system is configured to disable SMB sharing with the following command:

/bin/launchctl print-disabled system | /usr/bin/grep -c '"com.apple.smbd" => disabled'

If the result is not "1", this is a finding.)
  desc 'fix', 'Configure the macOS system to disable SMB sharing with the following command:

/bin/launchctl disable system/com.apple.smbd

The system may need a restart for the update to take effect.'
  impact 0.5
  tag check_id: 'C-81240r1148705_chk'
  tag severity: 'medium'
  tag gid: 'V-277085'
  tag rid: 'SV-277085r1268226_rule'
  tag stig_id: 'APPL-26-002001'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-81145r1148706_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
