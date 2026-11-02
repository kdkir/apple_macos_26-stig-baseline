control 'SV-277035' do
  title 'The macOS system must enforce time synchronization.'
  desc 'Time synchronization must be enforced on all networked systems.

This rule ensures the uniformity of time stamps for information systems with multiple system clocks and systems connected over a network.

'
  desc 'check', %q(Verify the macOS system is configured to enforce time synchronization with the following command:

/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.timed')\
.objectForKey('TMAutomaticTimeOnlyEnabled').js
EOS

If the result is not "true", this is a finding.)
  desc 'fix', 'Configure the macOS system to enforce time synchronization by installing the "com.apple.ManagedClient.preferences" configuration profile.'
  impact 0.5
  tag check_id: 'C-81190r1148555_chk'
  tag severity: 'medium'
  tag gid: 'V-277035'
  tag rid: 'SV-277035r1148557_rule'
  tag stig_id: 'APPL-26-000014'
  tag gtitle: 'SRG-OS-000355-GPOS-00143'
  tag fix_id: 'F-81095r1148556_fix'
  tag satisfies: ['SRG-OS-000355-GPOS-00143', 'SRG-OS-000356-GPOS-00144', 'SRG-OS-000785-GPOS-00250']
  tag 'documentable'
  tag cci: ['CCI-004923', 'CCI-004926', 'CCI-004922']
  tag nist: ['SC-45 (1) (a)', 'SC-45 (1) (b)', 'SC-45']

  describe macos_managed_preference('com.apple.timed', 'TMAutomaticTimeOnlyEnabled') do
    its('value') { should eq true }
  end
end
