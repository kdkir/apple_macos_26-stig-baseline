control 'SV-277124' do
  title 'The macOS system must disable Airplay Receiver.'
  desc 'Airplay Receiver allows users to send content from one Apple device to be displayed on the screen as it is being played from another device.

Support for Airplay Receiver is nonessential and must be disabled.

The information system must be configured to provide only essential capabilities.

'
  desc 'check', %q(Verify the macOS system is configured to disable Airplay Receiver with the following command:

/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowAirPlayIncomingRequests').js
EOS

If the result is not "false", this is a finding.)
  desc 'fix', 'Configure the macOS system to disable Airplay Receiver by installing the "com.apple.applicationaccess" configuration profile.'
  impact 0.5
  tag check_id: 'C-81279r1148822_chk'
  tag severity: 'medium'
  tag gid: 'V-277124'
  tag rid: 'SV-277124r1148824_rule'
  tag stig_id: 'APPL-26-002080'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-81184r1148823_fix'
  tag satisfies: ['SRG-OS-000095-GPOS-00049', 'SRG-OS-000300-GPOS-00118']
  tag 'documentable'
  tag cci: ['CCI-000381', 'CCI-001443']
  tag nist: ['CM-7 a', 'AC-18 (1)']

  describe macos_managed_preference('com.apple.applicationaccess', 'allowAirPlayIncomingRequests') do
    its('value') { should eq false }
  end
end
