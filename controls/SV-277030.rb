control 'SV-277030' do
  title 'The macOS system must enforce session lock no more than five seconds after screen saver is started.'
  desc 'A screen saver must be enabled and the system must be configured to require a password to unlock once the screen saver has been on for a maximum of five seconds.

An unattended system with an excessive grace period is vulnerable to a malicious user.'
  desc 'check', %q(Verify the macOS system is configured to initiate a session lock within five seconds of the screen saver starting with the following command:

/usr/bin/osascript -l JavaScript << EOS
function run() {
let delay = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.screensaver')\
.objectForKey('askForPasswordDelay'))
if ( delay <= 5 ) {
return("true")
} else {
return("false")
}
}
EOS

If the result is not "true", this is a finding.)
  desc 'fix', 'Configure the macOS system to initiate a session lock within five seconds of the screen saver starting by installing the "com.apple.screensaver" configuration profile.'
  impact 0.5
  tag check_id: 'C-81185r1148540_chk'
  tag severity: 'medium'
  tag gid: 'V-277030'
  tag rid: 'SV-277030r1148542_rule'
  tag stig_id: 'APPL-26-000003'
  tag gtitle: 'SRG-OS-000028-GPOS-00009'
  tag fix_id: 'F-81090r1148541_fix'
  tag 'documentable'
  tag cci: ['CCI-000056']
  tag nist: ['AC-11 b']

  describe macos_managed_preference('com.apple.screensaver', 'askForPasswordDelay') do
    its('value') { should_not be_nil }
    its('value') { should cmp <= 5 }
  end
end
