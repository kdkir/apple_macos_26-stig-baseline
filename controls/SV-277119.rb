control 'SV-277119' do
  title 'The macOS system must disable the guest account.'
  desc 'Guest access must be disabled.

Turning off guest access prevents anonymous users from accessing files.'
  desc 'check', %q(Verify the macOS system is configured to disable the guest account with the following command:

/usr/bin/osascript -l JavaScript << EOS
function run() {
let pref1 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.MCX')\
.objectForKey('DisableGuestAccount'))
let pref2 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.MCX')\
.objectForKey('EnableGuestAccount'))
if ( pref1 == true && pref2 == false ) {
return("true")
} else {
return("false")
}
}
EOS

If the result is not "true", this is a finding.)
  desc 'fix', 'Configure the macOS system to disable the guest account by installing the "com.apple.MCX" configuration profile.'
  impact 0.5
  tag check_id: 'C-81274r1148807_chk'
  tag severity: 'medium'
  tag gid: 'V-277119'
  tag rid: 'SV-277119r1148809_rule'
  tag stig_id: 'APPL-26-002063'
  tag gtitle: 'SRG-OS-000364-GPOS-00151'
  tag fix_id: 'F-81179r1148808_fix'
  tag 'documentable'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']

  describe macos_managed_preference('com.apple.MCX', 'DisableGuestAccount') do
    its('value') { should eq true }
  end

  describe macos_managed_preference('com.apple.MCX', 'EnableGuestAccount') do
    its('value') { should eq false }
  end
end
