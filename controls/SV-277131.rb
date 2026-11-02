control 'SV-277131' do
  title 'The macOS system must disable iCloud Game Center.'
  desc 'This works only with supervised devices (mobile device management [MDM]) and allows users to disable Apple Game Center. The rationale is that Game Center is using Apple ID and will share data on AppleID-based services; therefore, Game Center must be disabled.

This setting also prohibits the functionality of adding friends to Game Center.'
  desc 'check', %q(Verify the macOS system is configured to disable iCloud Game Center with the following command:

/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowGameCenter').js
EOS

If the result is not "false", this is a finding.)
  desc 'fix', 'Configure the macOS system to disable iCloud Game Center by installing the "com.apple.applicationaccess" configuration profile.'
  impact 0.5
  tag check_id: 'C-81286r1148843_chk'
  tag severity: 'medium'
  tag gid: 'V-277131'
  tag rid: 'SV-277131r1148845_rule'
  tag stig_id: 'APPL-26-002160'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-81191r1148844_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe macos_managed_preference('com.apple.applicationaccess', 'allowGameCenter') do
    its('value') { should eq false }
  end
end
