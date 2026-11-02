control 'SV-277049' do
  title 'The macOS system must enforce screen saver timeout.'
  desc 'The screen saver timeout must be set to 900 seconds or a shorter length of time.

This rule ensures that a full session lock is triggered within no more than 900 seconds of inactivity.'
  desc 'check', %q(Verify the macOS system is configured to initiate the screen saver timeout after 15 minutes of inactivity with the following command:

/usr/bin/osascript -l JavaScript << EOS
function run() {
let timeout = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.screensaver')\
.objectForKey('idleTime'))
if ( timeout <= 900 ) {
return("true")
} else {
return("false")
}
}
EOS

If the result is not "true", this is a finding.)
  desc 'fix', 'Configure the macOS system to initiate the screen saver after 15 minutes of inactivity by installing the "com.apple.screensaver" configuration profile.'
  impact 0.5
  tag check_id: 'C-81204r1148597_chk'
  tag severity: 'medium'
  tag gid: 'V-277049'
  tag rid: 'SV-277049r1148599_rule'
  tag stig_id: 'APPL-26-000070'
  tag gtitle: 'SRG-OS-000029-GPOS-00010'
  tag fix_id: 'F-81109r1148598_fix'
  tag 'documentable'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']

  describe macos_managed_preference('com.apple.screensaver', 'idleTime') do
    its('value') { should_not be_nil }
    its('value') { should cmp <= 900 }
  end
end
