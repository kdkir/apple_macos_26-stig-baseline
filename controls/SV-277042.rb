control 'SV-277042' do
  title 'The macOS system must disable FileVault automatic login.'
  desc 'If FileVault is enabled, automatic login must be disabled so that both FileVault and login window authentication are required.

The default behavior of macOS when FileVault is enabled is to automatically log in to the computer once successfully passing FileVault credentials.

Note: DisableFDEAutoLogin does not have to be set on Apple Silicon-based macOS systems that are smart card enforced, as smart cards are available at preboot.'
  desc 'check', %q(Verify the macOS system is configured to disable FileVault automatic login with the following command:

/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.loginwindow')\
.objectForKey('DisableFDEAutoLogin').js
EOS

If the result is not "true", this is a finding.)
  desc 'fix', 'Configure the macOS system to disable FileVault automatic login by installing the "com.apple.loginwindow" configuration profile.

Note: To ensure continued access to the operating system, consult the supplemental guidance provided with the STIG before applying the configuration profile.'
  impact 0.5
  tag check_id: 'C-81197r1148576_chk'
  tag severity: 'medium'
  tag gid: 'V-277042'
  tag rid: 'SV-277042r1268226_rule'
  tag stig_id: 'APPL-26-000033'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-81102r1148577_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
