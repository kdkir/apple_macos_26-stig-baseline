control 'SV-277174' do
  title 'The macOS system must disable Erase Content and Settings.'
  desc 'Erase Content and Settings must be disabled.

Without disabling the Erase Content and Settings configuration, forensics data could be lost if this feature is activated on a compromised system.'
  desc 'check', %q(Verify the macOS system is configured to disable Erase Content and Settings with the following command:

/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowEraseContentAndSettings').js
EOS

If the result is not "false", this is a finding.)
  desc 'fix', 'Configure the macOS system to disable Erase Content and Settings by installing the "com.apple.applicationaccess" configuration profile.'
  impact 0.5
  tag check_id: 'C-81329r1148972_chk'
  tag severity: 'medium'
  tag gid: 'V-277174'
  tag rid: 'SV-277174r1148974_rule'
  tag stig_id: 'APPL-26-005061'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-81234r1148973_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
