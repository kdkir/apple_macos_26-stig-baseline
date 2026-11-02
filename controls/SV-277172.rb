control 'SV-277172' do
  title 'The macOS system must disable Handoff.'
  desc 'Handoff must be disabled.

Handoff allows users to continue working on a document or project when the user switches from one Apple device to another. Disabling Handoff prevents data transfers to unauthorized devices.

'
  desc 'check', %q(Verify the macOS system is configured to disable Handoff with the following command:

/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowActivityContinuation').js
EOS

If the result is not "false", this is a finding.)
  desc 'fix', 'Configure the macOS system to disable Handoff by installing the "com.apple.applicationaccess" configuration profile.'
  impact 0.5
  tag check_id: 'C-81327r1148966_chk'
  tag severity: 'medium'
  tag gid: 'V-277172'
  tag rid: 'SV-277172r1268226_rule'
  tag stig_id: 'APPL-26-005058'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-81232r1148967_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000095-GPOS-00049', 'SRG-OS-000300-GPOS-00118']
  tag 'documentable'
  tag cci: ['CCI-000213', 'CCI-000381', 'CCI-001443']
  tag nist: ['AC-3', 'CM-7 a', 'AC-18 (1)']
end
