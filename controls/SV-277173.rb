control 'SV-277173' do
  title 'The macOS system must disable proximity-based password sharing requests.'
  desc 'Proximity-based password sharing requests must be disabled.

The default behavior of macOS is to allow users to request passwords from other known devices (macOS and iOS). This feature must be disabled to prevent passwords from being shared.'
  desc 'check', %q(Verify the macOS system is configured to disable proximity-based password sharing requests with the following command:

/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowPasswordProximityRequests').js
EOS

If the result is not "false", this is a finding.)
  desc 'fix', 'Configure the macOS system to disable proximity-based password sharing requests by installing the "com.apple.applicationaccess" configuration profile.'
  impact 0.5
  tag check_id: 'C-81328r1148969_chk'
  tag severity: 'medium'
  tag gid: 'V-277173'
  tag rid: 'SV-277173r1148971_rule'
  tag stig_id: 'APPL-26-005060'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-81233r1148970_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe macos_managed_preference('com.apple.applicationaccess', 'allowPasswordProximityRequests') do
    its('value') { should eq false }
  end
end
