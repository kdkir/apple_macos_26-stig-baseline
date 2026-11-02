control 'SV-277171' do
  title 'The macOS system must disable Unlock with Apple Watch during Setup Assistant.'
  desc 'The prompt for Apple Watch unlock setup during Setup Assistant must be disabled.

Disabling Apple watches is a necessary step to ensuring the information system retains a session lock until the user reestablishes access using authorized identification and authentication procedures.'
  desc 'check', %q(Verify the macOS system is configured to disable Unlock with Apple Watch during Setup Assistant with the following command:

/usr/bin/osascript -l JavaScript 2>/dev/null << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SetupAssistant.managed')\
.objectForKey('SkipSetupItems').containsObject("WatchMigration")
EOS

If the result is not "true", this is a finding.)
  desc 'fix', 'Configure the macOS system to disable Unlock with Apple Watch during Setup Assistant by installing the "com.apple.SetupAssistant.managed" configuration profile.'
  impact 0.5
  tag check_id: 'C-81326r1149350_chk'
  tag severity: 'medium'
  tag gid: 'V-277171'
  tag rid: 'SV-277171r1149402_rule'
  tag stig_id: 'APPL-26-005056'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-81231r1148964_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe macos_managed_preference('com.apple.SetupAssistant.managed', 'SkipSetupItems') do
    its('value') { should include 'WatchMigration' }
  end
end
