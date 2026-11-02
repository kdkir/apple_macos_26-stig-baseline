control 'SV-277092' do
  title 'The macOS system must disable AirDrop.'
  desc 'AirDrop must be disabled to prevent file transfers to or from unauthorized devices.

AirDrop allows users to share and receive files from other nearby Apple devices.

'
  desc 'check', %q(Verify the macOS system is configured to disable AirDrop with the following command:

/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowAirDrop').js
EOS

If the result is not "false", this is a finding.)
  desc 'fix', 'Configure the macOS system to disable AirDrop by installing the "com.apple.applicationaccess" configuration profile.'
  impact 0.5
  tag check_id: 'C-81247r1148726_chk'
  tag severity: 'medium'
  tag gid: 'V-277092'
  tag rid: 'SV-277092r1268226_rule'
  tag stig_id: 'APPL-26-002009'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-81152r1148727_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000095-GPOS-00049', 'SRG-OS-000300-GPOS-00118']
  tag 'documentable'
  tag cci: ['CCI-000213', 'CCI-000381', 'CCI-001443']
  tag nist: ['AC-3', 'CM-7 a', 'AC-18 (1)']

  describe macos_managed_preference('com.apple.applicationaccess', 'allowAirDrop') do
    its('value') { should eq false }
  end
end
