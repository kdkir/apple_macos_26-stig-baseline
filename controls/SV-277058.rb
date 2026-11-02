control 'SV-277058' do
  title 'The macOS system must enable the time synchronization daemon.'
  desc 'The macOS time synchronization daemon (timed) must be enabled for proper time synchronization to an authorized time server.

Note: The time synchronization daemon is enabled by default on macOS.

'
  desc 'check', %q(Verify the macOS system is configured to enable the time synchronization daemon with the following command:

/bin/launchctl print system | /usr/bin/grep -c -E '\tcom.apple.timed'

If the result is not "1", this is a finding.)
  desc 'fix', 'Configure the macOS system to enable the time synchronization daemon with the following command:

/bin/launchctl load -w /System/Library/LaunchDaemons/com.apple.timed.plist

Note: The service "timed" cannot be unloaded or loaded while System Integrity Protection (SIP) is enabled.'
  impact 0.5
  tag check_id: 'C-81213r1149354_chk'
  tag severity: 'medium'
  tag gid: 'V-277058'
  tag rid: 'SV-277058r1149404_rule'
  tag stig_id: 'APPL-26-000180'
  tag gtitle: 'SRG-OS-000355-GPOS-00143'
  tag fix_id: 'F-81118r1148625_fix'
  tag satisfies: ['SRG-OS-000355-GPOS-00143', 'SRG-OS-000356-GPOS-00144', 'SRG-OS-000785-GPOS-00250']
  tag 'documentable'
  tag cci: ['CCI-004923', 'CCI-004926', 'CCI-004922']
  tag nist: ['SC-45 (1) (a)', 'SC-45 (1) (b)', 'SC-45']

  describe macos_launchd_service('com.apple.timed') do
    it { should be_loaded }
  end
end
