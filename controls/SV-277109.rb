control 'SV-277109' do
  title 'The macOS system must disable Siri Setup during Setup Assistant.'
  desc 'The prompt for Siri during Setup Assistant must be disabled.

Organizations must apply organizationwide configuration settings. The macOS Siri Assistant Setup prompt guides new users through enabling their own specific Siri settings. This is not essential and, therefore, must be disabled to prevent the risk of individuals electing Siri settings with the potential to override organizationwide settings.'
  desc 'check', %q(Verify the macOS system is configured to disable Siri Setup during Setup Assistant with the following command:

/usr/bin/osascript -l JavaScript 2>/dev/null << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SetupAssistant.managed')\
.objectForKey('SkipSetupItems').containsObject("Siri")
EOS

If the result is not "true", this is a finding.)
  desc 'fix', 'Configure the macOS system to disable Siri Setup during Setup Assistant by installing the "com.apple.SetupAssistant.managed" configuration profile.'
  impact 0.5
  tag check_id: 'C-81264r1149344_chk'
  tag severity: 'medium'
  tag gid: 'V-277109'
  tag rid: 'SV-277109r1149399_rule'
  tag stig_id: 'APPL-26-002039'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-81169r1148778_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe macos_managed_preference('com.apple.SetupAssistant.managed', 'SkipSetupItems') do
    its('value') { should include 'Siri' }
  end
end
