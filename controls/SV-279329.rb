control 'SV-279329' do
  title 'The macOS system must disable Apple Intelligence during Setup Assistant.'
  desc 'The prompt for Apple Intelligence setup during Setup Assistant must be disabled.

Disabling Apple watches is a necessary step to ensuring the information system retains a session lock until the user reestablishes access using authorized identification and authentication procedures.'
  desc 'check', %q(Verify the macOS system is configured to skip Apple Intelligence during Setup Assistant with the following command:

/usr/bin/osascript -l JavaScript 2>/dev/null << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SetupAssistant.managed')\
.objectForKey('SkipSetupItems').containsObject("Intelligence")
EOS

If the result is not "true", this is a finding.)
  desc 'fix', 'Configure the macOS system to skip Apple Intelligence during Setup Assistant by installing the "com.apple.SetupAssistant.managed" configuration profile.'
  impact 0.5
  tag check_id: 'C-83880r1149388_chk'
  tag severity: 'medium'
  tag gid: 'V-279329'
  tag rid: 'SV-279329r1207646_rule'
  tag stig_id: 'APPL-26-005170'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-83785r1207645_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe macos_managed_preference('com.apple.SetupAssistant.managed', 'SkipSetupItems') do
    its('value') { should include 'Intelligence' }
  end
end
