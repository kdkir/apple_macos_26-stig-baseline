control 'SV-277183' do
  title 'The macOS system must disable Apple Intelligence Image Playground.'
  desc 'Apple Intelligence features such as Image Playground must be disabled.

Using off-device AI poses a data loss risk.'
  desc 'check', %q(Verify the macOS system is configured to disable Apple Intelligence Image Playground with the following command:

/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowImagePlayground').js
EOS

If the result is not "false", this is a finding.)
  desc 'fix', 'Configure the macOS system to disable Apple Intelligence Image Playground by installing the "com.apple.applicationaccess" configuration profile.'
  impact 0.5
  tag check_id: 'C-81338r1149374_chk'
  tag severity: 'medium'
  tag gid: 'V-277183'
  tag rid: 'SV-277183r1149414_rule'
  tag stig_id: 'APPL-26-005150'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-81243r1149375_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe macos_managed_preference('com.apple.applicationaccess', 'allowImagePlayground') do
    its('value') { should eq false }
  end
end
