control 'SV-277148' do
  title 'The macOS system must disable password hints.'
  desc 'Password hints must be disabled.

Password hints leak information about passwords that are currently in use and can lead to loss of confidentiality.'
  desc 'check', %q(Verify the macOS system is configured to disable password hints with the following command:

/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.loginwindow')\
.objectForKey('RetriesUntilHint').js
EOS

If the result is not "0", this is a finding.)
  desc 'fix', 'Configure the macOS system to disable password hints by installing the "com.apple.loginwindow" configuration profile.'
  impact 0.5
  tag check_id: 'C-81303r1148894_chk'
  tag severity: 'medium'
  tag gid: 'V-277148'
  tag rid: 'SV-277148r1148896_rule'
  tag stig_id: 'APPL-26-003012'
  tag gtitle: 'SRG-OS-000079-GPOS-00047'
  tag fix_id: 'F-81208r1148895_fix'
  tag 'documentable'
  tag cci: ['CCI-000206']
  tag nist: ['IA-6']

  describe macos_managed_preference('com.apple.loginwindow', 'RetriesUntilHint') do
    its('value') { should eq 0 }
  end
end
