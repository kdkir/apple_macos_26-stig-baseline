control 'SV-277031' do
  title 'The macOS system must configure user session lock when a smart token is removed.'
  desc 'The screen lock must be configured to initiate automatically when the smart token is removed from the system.

Session locks are temporary actions taken when users stop work and move away from the immediate vicinity of the information system but do not want to log out because of the temporary nature of their absences. While a session lock is not an acceptable substitute for logging out of an information system for longer periods of time, they prevent a malicious user from accessing the information system when a user has removed their smart token.

[IMPORTANT]
====
Information system security officers (ISSOs) may make the risk-based decision not to enforce a session lock when a smart token is removed to maintain necessary workflow capabilities, but they are advised to first fully weigh the potential risks posed to their organization.
===='
  desc 'check', %q(Verify the macOS system is configured to lock the user session when a smart token is removed with the following command:

/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.security.smartcard')\
.objectForKey('tokenRemovalAction').js
EOS

If the result is not "1", this is a finding.)
  desc 'fix', 'Configure the macOS system to lock the user session when a smart token is removed by installing the "com.apple.security.smartcard" configuration profile.

Note: To ensure continued access to the operating system, consult the supplemental guidance provided with the STIG before applying the configuration profile.'
  impact 0.5
  tag check_id: 'C-81186r1148543_chk'
  tag severity: 'medium'
  tag gid: 'V-277031'
  tag rid: 'SV-277031r1148545_rule'
  tag stig_id: 'APPL-26-000005'
  tag gtitle: 'SRG-OS-000030-GPOS-00011'
  tag fix_id: 'F-81091r1148544_fix'
  tag 'documentable'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']

  describe macos_managed_preference('com.apple.security.smartcard', 'tokenRemovalAction') do
    its('value') { should eq 1 }
  end
end
