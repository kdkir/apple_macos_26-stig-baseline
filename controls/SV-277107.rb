control 'SV-277107' do
  title 'The macOS system must disable iCloud storage setup during Setup Assistant.'
  desc 'The prompt to set up iCloud storage services during Setup Assistant must be disabled.

The default behavior of macOS is to prompt new users to set up storage in iCloud. Disabling the iCloud storage setup prompt provides organizations with more control over their data storage.'
  desc 'check', %q(Verify the macOS system is configured to disable iCloud storage setup during Setup Assistant with the following command:

/usr/bin/osascript -l JavaScript 2>/dev/null << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SetupAssistant.managed')\
.objectForKey('skipSetupItems').containsObject("iCloudStorage")
EOS

If the result is not "true", this is a finding.)
  desc 'fix', 'Configure the macOS system to disable iCloud storage setup during Setup Assistant by installing the "com.apple.SetupAssistant.managed" configuration profile.'
  impact 0.5
  tag check_id: 'C-81262r1149382_chk'
  tag severity: 'medium'
  tag gid: 'V-277107'
  tag rid: 'SV-277107r1149418_rule'
  tag stig_id: 'APPL-26-002037'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-81167r1148772_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe macos_managed_preference('com.apple.SetupAssistant.managed', 'SkipSetupItems') do
    its('value') { should include 'iCloudStorage' }
  end
end
