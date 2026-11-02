control 'SV-277121' do
  title 'The macOS system must disable unattended or automatic login to the system.'
  desc 'Automatic login must be disabled.

When automatic logins are enabled, the default user account is automatically logged on at boot time without prompting the user for a password. Even if the screen is later locked, a malicious user would be able to reboot the computer and find it already logged in. Disabling automatic logins mitigates this risk.

'
  desc 'check', %q(Verify the macOS system is configured to disable unattended or automatic login to the system with the following command:

/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.loginwindow')\
.objectForKey('com.apple.login.mcx.DisableAutoLoginClient').js
EOS

If the result is not "true", this is a finding.)
  desc 'fix', 'Configure the macOS system to disable unattended or automatic login to the system by installing the "com.apple.loginwindow" configuration profile.'
  impact 0.7
  tag check_id: 'C-81276r1148813_chk'
  tag severity: 'high'
  tag gid: 'V-277121'
  tag rid: 'SV-277121r1148815_rule'
  tag stig_id: 'APPL-26-002066'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-81181r1148814_fix'
  tag satisfies: ['SRG-OS-000104-GPOS-00051', 'SRG-OS-000480-GPOS-00229']
  tag 'documentable'
  tag cci: ['CCI-000764', 'CCI-000366']
  tag nist: ['IA-2', 'CM-6 b']
end
