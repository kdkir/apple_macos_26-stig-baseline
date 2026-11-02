control 'SV-277105' do
  title 'The macOS system must disable Apple ID setup during Setup Assistant.'
  desc 'The prompt for Apple ID setup during Setup Assistant must be disabled.

macOS will automatically prompt new users to set up an Apple ID while they are going through Setup Assistant if this is not disabled. This can mislead new users into thinking they need to create Apple ID accounts upon their first login.'
  desc 'check', %q(Verify the macOS system is configured to disable Apple ID setup during Setup Assistant with the following command:

/usr/bin/osascript -l JavaScript 2>/dev/null << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SetupAssistant.managed')\
.objectForKey('SkipSetupItems').containsObject("AppleID")
EOS

If the result is not "true", this is a finding.)
  desc 'fix', 'Configure the macOS system to disable Apple ID setup during Setup Assistant by installing the "com.apple.SetupAssistant.managed" configuration profile.'
  impact 0.5
  tag check_id: 'C-81260r1149358_chk'
  tag severity: 'medium'
  tag gid: 'V-277105'
  tag rid: 'SV-277105r1149406_rule'
  tag stig_id: 'APPL-26-002035'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-81165r1148766_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe macos_managed_preference('com.apple.SetupAssistant.managed', 'SkipSetupItems') do
    its('value') { should include 'AppleID' }
  end
end
