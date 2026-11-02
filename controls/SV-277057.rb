control 'SV-277057' do
  title 'The macOS system must be configured to use an authorized time server.'
  desc 'An approved time server must be the only server configured for use. As of macOS 10.13, only one time server is supported.

This rule ensures the uniformity of time stamps for information systems with multiple system clocks and systems connected over a network.

'
  desc 'check', "Verify the macOS system is configured to use an authorized time server with the following command:

/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.MCX')\\
.objectForKey('timeServer').js
EOS

If the result is not an authoritative time server that is synchronized with redundant USNO time servers as designated for the appropriate DoW network, this is a finding."
  desc 'fix', 'Configure the macOS system to use an authorized time server by installing the "com.apple.MCX" configuration profile.'
  impact 0.5
  tag check_id: 'C-81212r1268027_chk'
  tag severity: 'medium'
  tag gid: 'V-277057'
  tag rid: 'SV-277057r1268028_rule'
  tag stig_id: 'APPL-26-000170'
  tag gtitle: 'SRG-OS-000355-GPOS-00143'
  tag fix_id: 'F-81117r1148622_fix'
  tag satisfies: ['SRG-OS-000355-GPOS-00143', 'SRG-OS-000356-GPOS-00144']
  tag 'documentable'
  tag cci: ['CCI-004923', 'CCI-004926']
  tag nist: ['SC-45 (1) (a)', 'SC-45 (1) (b)']

  approved_time_servers = input('approved_time_servers')
  time_servers = macos_managed_preference('com.apple.MCX', 'timeServer').value.to_s.split(/[\s,]+/).reject(&:empty?)

  describe 'Time servers configured in com.apple.MCX timeServer' do
    subject { time_servers }
    it { should_not be_empty }
    it { should all be_in approved_time_servers }
  end
end
