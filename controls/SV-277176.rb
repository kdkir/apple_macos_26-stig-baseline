control 'SV-277176' do
  title 'The macOS system must prohibit user installation of software into /users/.'
  desc 'Users must not be allowed to install software into /users/.

Allowing regular users without explicit privileges to install software presents the risk of untested and potentially malicious software being installed on the system. Explicit privileges (escalated or administrative privileges) provide the regular user with explicit capabilities and control that exceeds the rights of a regular user.

[IMPORTANT]
====
Apple has deprecated the use of application restriction controls (https://github.com/apple/device-management/blob/eb51fb0cb9626cac4717858556912c257a734ce0/mdm/profiles/com.apple.applicationaccess.new.yaml#L67-L70). Using these controls may not work as expected. Third party software may be required to fulfill the compliance requirements.
===='
  desc 'check', %q(Verify the macOS system is configured to prohibit user installation of software into /users/ with the following command:

/usr/bin/osascript -l JavaScript << EOS
function run() {
let pref1 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess.new')\
.objectForKey('familyControlsEnabled'))
let pathlist = $.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess.new')\
.objectForKey('pathBlackList').js
for ( let app in pathlist ) {
if ( ObjC.unwrap(pathlist[app]) == "/Users/" && pref1 == true ){
return("true")
}
}
return("false")
}
EOS

If the result is not "true", this is a finding.)
  desc 'fix', 'Configure the macOS system to prohibit user installation of software into /users/ by installing the "com.apple.applicationaccess.new" configuration profile.'
  impact 0.5
  tag check_id: 'C-81331r1148978_chk'
  tag severity: 'medium'
  tag gid: 'V-277176'
  tag rid: 'SV-277176r1148980_rule'
  tag stig_id: 'APPL-26-005080'
  tag gtitle: 'SRG-OS-000362-GPOS-00149'
  tag fix_id: 'F-81236r1148979_fix'
  tag 'documentable'
  tag cci: ['CCI-003980']
  tag nist: ['CM-11 (2)']

  describe macos_managed_preference('com.apple.applicationaccess.new', 'familyControlsEnabled') do
    its('value') { should eq true }
  end

  describe macos_managed_preference('com.apple.applicationaccess.new', 'pathBlackList') do
    its('value') { should include '/Users/' }
  end
end
