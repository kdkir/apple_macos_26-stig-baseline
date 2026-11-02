control 'SV-277106' do
  title 'The macOS system must disable Privacy Setup services during Setup Assistant.'
  desc 'The prompt for Privacy Setup services during Setup Assistant must be disabled.

Organizations must apply organizationwide configuration settings. The macOS Privacy Setup services prompt guides new users through enabling their own specific privacy settings. This is not essential and, therefore, must be disabled to prevent the risk of individuals electing privacy settings with the potential to override organizationwide settings.'
  desc 'check', %q(Verify the macOS system is configured to disable Privacy Setup services during Setup Assistant with the following command:

/usr/bin/osascript -l JavaScript 2>/dev/null << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SetupAssistant.managed')\
.objectForKey('SkipSetupItems').containsObject("Privacy")
EOS

If the result is not "true", this is a finding.)
  desc 'fix', 'Configure the macOS system to disable Privacy Setup services during Setup Assistant by installing the "com.apple.SetupAssistant.managed" configuration profile.'
  impact 0.5
  tag check_id: 'C-81261r1149342_chk'
  tag severity: 'medium'
  tag gid: 'V-277106'
  tag rid: 'SV-277106r1149398_rule'
  tag stig_id: 'APPL-26-002036'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-81166r1148769_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
