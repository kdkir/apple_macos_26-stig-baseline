control 'SV-277142' do
  title 'The macOS system must disable iPhone Mirroring.'
  desc 'iPhone Mirroring must be disabled to prevent file transfers to or from unauthorized devices. 

Disabling iPhone Mirroring also prevents potentially unauthorized applications from appearing as if they are installed on the Mac.

'
  desc 'check', %q(Verify the macOS system is configured to disable iPhone Mirroring with the following command:

/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowiPhoneMirroring').js
EOS

If the result is not "false", this is a finding.)
  desc 'fix', 'Configure the macOS system to disable iPhone Mirroring by installing the "com.apple.applicationaccess" configuration profile.'
  impact 0.5
  tag check_id: 'C-81297r1148876_chk'
  tag severity: 'medium'
  tag gid: 'V-277142'
  tag rid: 'SV-277142r1268226_rule'
  tag stig_id: 'APPL-26-002271'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-81202r1148877_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000095-GPOS-00049', 'SRG-OS-000300-GPOS-00118']
  tag 'documentable'
  tag cci: ['CCI-000213', 'CCI-000381', 'CCI-001443']
  tag nist: ['AC-3', 'CM-7 a', 'AC-18 (1)']
end
