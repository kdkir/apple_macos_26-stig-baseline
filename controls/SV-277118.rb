control 'SV-277118' do
  title 'The macOS system must disable Bluetooth when no approved device is connected.'
  desc 'The macOS system must be configured to disable Bluetooth unless an approved device is connected.

[IMPORTANT]
====
Information system security officers (ISSOs) may make the risk-based decision not to disable Bluetooth to maintain necessary functionality, but they are advised to first fully weigh the potential risks posed to their organization.
====

'
  desc 'check', %q(Verify the macOS system is configured to disable Bluetooth with the following command:

/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.MCXBluetooth')\
.objectForKey('DisableBluetooth').js
EOS

If the result is not "true", this is a finding.)
  desc 'fix', 'Configure the macOS system to disable Bluetooth by installing the "com.apple.MCXBluetooth" configuration profile.'
  impact 0.7
  tag check_id: 'C-81273r1148804_chk'
  tag severity: 'high'
  tag gid: 'V-277118'
  tag rid: 'SV-277118r1148806_rule'
  tag stig_id: 'APPL-26-002062'
  tag gtitle: 'SRG-OS-000423-GPOS-00187'
  tag fix_id: 'F-81178r1148805_fix'
  tag satisfies: ['SRG-OS-000423-GPOS-00187', 'SRG-OS-000481-GPOS-00481']
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']

  describe macos_managed_preference('com.apple.MCXBluetooth', 'DisableBluetooth') do
    its('value') { should eq true }
  end
end
