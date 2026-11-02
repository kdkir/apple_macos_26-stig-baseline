control 'SV-277182' do
  title 'The macOS system must disable Genmoji AI Creation.'
  desc 'Apple Intelligence features such as Genmoji must be disabled.

Using off-device AI poses a data loss risk.'
  desc 'check', %q(Verify the macOS system is configured to disable Genmoji with the following command:

/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowGenmoji').js
EOS

If the result is not "false", this is a finding.)
  desc 'fix', 'Configure the macOS system to disable Genmoji by installing the "com.apple.applicationaccess" configuration profile.'
  impact 0.5
  tag check_id: 'C-81337r1148996_chk'
  tag severity: 'medium'
  tag gid: 'V-277182'
  tag rid: 'SV-277182r1149416_rule'
  tag stig_id: 'APPL-26-005140'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-81242r1148997_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
