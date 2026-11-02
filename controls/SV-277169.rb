control 'SV-277169' do
  title 'The macOS system must disable the TouchID prompt during Setup Assistant.'
  desc 'The prompt for TouchID during Setup Assistant must be disabled.

macOS prompts new users through enabling TouchID during Setup Assistant; this is not essential and, therefore, must be disabled to prevent the risk of individuals electing to enable TouchID to override organizationwide settings.'
  desc 'check', %q(Verify the macOS system is configured to disable the TouchID prompt during Setup Assistant with the following command:

/usr/bin/osascript -l JavaScript 2>/dev/null << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SetupAssistant.managed')\
.objectForKey('SkipSetupItems').containsObject("Biometric")
EOS

If the result is not "true", this is a finding.)
  desc 'fix', 'Configure the macOS system to disable the TouchID prompt during Setup Assistant by installing the "com.apple.SetupAssistant.managed" configuration profile.'
  impact 0.5
  tag check_id: 'C-81324r1149346_chk'
  tag severity: 'medium'
  tag gid: 'V-277169'
  tag rid: 'SV-277169r1149400_rule'
  tag stig_id: 'APPL-26-005054'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-81229r1148958_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
