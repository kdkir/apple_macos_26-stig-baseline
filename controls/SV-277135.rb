control 'SV-277135' do
  title 'The macOS system must disable sending Siri and Dictation information to Apple.'
  desc 'The ability for Apple to store and review audio of Siri and Dictation interactions must be disabled.

The information system must be configured to provide only essential capabilities. Disabling the submission of Siri and Dictation information will mitigate the risk of unwanted data being sent to Apple.'
  desc 'check', %q(Verify the macOS system is configured to disable sending Siri and Dictation information to Apple with the following command:

/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.assistant.support')\
.objectForKey('Siri Data Sharing Opt-In Status').js
EOS

If the result is not "2", this is a finding.)
  desc 'fix', 'Configure the macOS system to disable sending Siri and Dictation information to Apple by installing the "com.apple.assistant.support" configuration profile.'
  impact 0.5
  tag check_id: 'C-81290r1148855_chk'
  tag severity: 'medium'
  tag gid: 'V-277135'
  tag rid: 'SV-277135r1148857_rule'
  tag stig_id: 'APPL-26-002210'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-81195r1148856_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe macos_managed_preference('com.apple.assistant.support', 'Siri Data Sharing Opt-In Status') do
    its('value') { should eq 2 }
  end
end
