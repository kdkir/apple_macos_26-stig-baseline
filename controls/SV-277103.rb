control 'SV-277103' do
  title 'The macOS system must disable sending audio recordings and transcripts to Apple.'
  desc 'The ability for Apple to store and review audio recordings and transcripts of vocal shortcuts and voice control interactions must be disabled.

The information system must be configured to provide only essential capabilities. Disabling the submission of this information will mitigate the risk of unwanted data being sent to Apple.'
  desc 'check', %q(Verify the macOS system is configured to disable sending audio recordings and transcripts with the following command:

/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.Accessibility')\
.objectForKey('AXSAudioDonationSiriImprovementEnabled').js
EOS

If the result is not "false", this is a finding.)
  desc 'fix', 'Configure the macOS system to disable sending audio recordings and transcripts by installing the "com.apple.accessibility" configuration profile.'
  impact 0.5
  tag check_id: 'C-81258r1148759_chk'
  tag severity: 'medium'
  tag gid: 'V-277103'
  tag rid: 'SV-277103r1148761_rule'
  tag stig_id: 'APPL-26-002023'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-81163r1148760_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe macos_managed_preference('com.apple.Accessibility', 'AXSAudioDonationSiriImprovementEnabled') do
    its('value') { should eq false }
  end
end
