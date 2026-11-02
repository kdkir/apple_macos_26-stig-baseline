control 'SV-277104' do
  title 'The macOS system must disable sending search data from Spotlight to Apple.'
  desc 'Sending data to Apple to help improve search must be disabled.

The information system must be configured to provide only essential capabilities. Disabling the submission of search data will mitigate the risk of unwanted data being sent to Apple.'
  desc 'check', %q(Verify the macOS system is configured to disable sending search data from Spotlight with the following command:

/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.assistant.support')\
.objectForKey('Search Queries Data Sharing Status').js
EOS

If the result is not "2", this is a finding.)
  desc 'fix', 'Configure the macOS system to disable sending search data from Spotlight by installing the "com.apple.assistant.support" configuration profile.'
  impact 0.5
  tag check_id: 'C-81259r1148762_chk'
  tag severity: 'medium'
  tag gid: 'V-277104'
  tag rid: 'SV-277104r1148764_rule'
  tag stig_id: 'APPL-26-002024'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-81164r1148763_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe macos_managed_preference('com.apple.assistant.support', 'Search Queries Data Sharing Status') do
    its('value') { should eq 2 }
  end
end
