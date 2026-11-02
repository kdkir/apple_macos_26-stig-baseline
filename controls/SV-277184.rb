control 'SV-277184' do
  title 'The macOS system must disable Apple Intelligence Writing Tools.'
  desc 'Apple Intelligence features that use off device Artificial Intelligence (AI) must be disabled.

Using off-device AI poses a data loss risk.'
  desc 'check', %q(Verify the macOS system is configured to disable Apple Intelligence Writing Tools with the following command:

/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowWritingTools').js
EOS

If the result is not "false", this is a finding.)
  desc 'fix', 'Configure the macOS system to disable Apple Intelligence Writing Tools by installing the "com.apple.applicationaccess" configuration profile.'
  impact 0.5
  tag check_id: 'C-81339r1149002_chk'
  tag severity: 'medium'
  tag gid: 'V-277184'
  tag rid: 'SV-277184r1149004_rule'
  tag stig_id: 'APPL-26-005160'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-81244r1149003_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe macos_managed_preference('com.apple.applicationaccess', 'allowWritingTools') do
    its('value') { should eq false }
  end
end
