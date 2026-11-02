control 'SV-277137' do
  title 'The macOS system must disable Dictation.'
  desc 'Dictation must be disabled on Intel-based Macs as the feature On Device Dictation is only available on Apple Silicon devices.'
  desc 'check', %q(For Apple Silicon-based systems, this is not applicable.

Verify the macOS system is configured to disable Dictation with the following command:

/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowDictation').js
EOS

If the result is not "false", this is a finding.)
  desc 'fix', 'Configure the macOS system to disable Dictation by installing the "com.apple.applicationaccess" configuration profile.'
  impact 0.5
  tag check_id: 'C-81292r1148861_chk'
  tag severity: 'medium'
  tag gid: 'V-277137'
  tag rid: 'SV-277137r1148863_rule'
  tag stig_id: 'APPL-26-002230'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-81197r1148862_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
