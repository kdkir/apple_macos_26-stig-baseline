control 'SV-277170' do
  title 'The macOS system must disable the Screen Time prompt during Setup Assistant.'
  desc 'The prompt for Screen Time setup during Setup Assistant must be disabled.

Enabling any service increases the attack surface for an intruder. By disabling unnecessary services, the attack surface is minimized.'
  desc 'check', %q(Verify the macOS system is configured to disable the Screen Time prompt during Setup Assistant with the following command:

/usr/bin/osascript -l JavaScript 2>/dev/null << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SetupAssistant.managed')\
.objectForKey('SkipSetupItems').containsObject("ScreenTime")
EOS

If the result is not "true", this is a finding.)
  desc 'fix', 'Configure the macOS system to disable the Screen Time prompt during Setup Assistant by installing the "com.apple.SetupAssistant.managed" configuration profile.'
  impact 0.5
  tag check_id: 'C-81325r1149348_chk'
  tag severity: 'medium'
  tag gid: 'V-277170'
  tag rid: 'SV-277170r1149401_rule'
  tag stig_id: 'APPL-26-005055'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-81230r1148961_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe macos_managed_preference('com.apple.SetupAssistant.managed', 'SkipSetupItems') do
    its('value') { should include 'ScreenTime' }
  end
end
