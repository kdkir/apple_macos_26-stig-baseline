control 'SV-277029' do
  title 'The macOS system must enforce screen saver password.'
  desc "Users must authenticate when unlocking the screen saver.

The screen saver acts as a session lock and prevents unauthorized users from accessing the current user's account."
  desc 'check', %q(Verify the macOS system is configured to prompt users to enter a password to unlock the screen saver with the following command:

/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.screensaver')\
.objectForKey('askForPassword').js
EOS

If the result is not "true", this is a finding.)
  desc 'fix', 'Configure the macOS system to prompt users to enter a password to unlock the screen saver by installing the "com.apple.screensaver" configuration profile.'
  impact 0.5
  tag check_id: 'C-81184r1148537_chk'
  tag severity: 'medium'
  tag gid: 'V-277029'
  tag rid: 'SV-277029r1148539_rule'
  tag stig_id: 'APPL-26-000002'
  tag gtitle: 'SRG-OS-000028-GPOS-00009'
  tag fix_id: 'F-81089r1148538_fix'
  tag 'documentable'
  tag cci: ['CCI-000056']
  tag nist: ['AC-11 b']
end
