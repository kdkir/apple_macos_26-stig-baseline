control 'SV-277133' do
  title 'The macOS system must disable Find My service.'
  desc "The Find My service must be disabled.

A Mobile Device Management (MDM) solution must be used to carry out remote locking and wiping instead of Apple's Find My service.

Apple's Find My service uses a personal AppleID for authentication. Organizations must rely on MDM solutions, which have much more secure authentication requirements, to perform remote lock and remote wipe."
  desc 'check', %q(Verify the macOS system is configured to disable Find My service with the following command:

/usr/bin/osascript -l JavaScript << EOS
function run() {
let pref1 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowFindMyDevice'))
let pref2 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowFindMyFriends'))
let pref3 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.icloud.managed')\
.objectForKey('DisableFMMiCloudSetting'))
if ( pref1 == false && pref2 == false && pref3 == true ) {
return("true")
} else {
return("false")
}
}
EOS

If the result is not "true", this is a finding.)
  desc 'fix', 'Configure the macOS system to disable Find My service by installing the "com.apple.applicationaccess" and "com.apple.icloud.managed"configuration profiles.'
  impact 0.5
  tag check_id: 'C-81288r1148849_chk'
  tag severity: 'medium'
  tag gid: 'V-277133'
  tag rid: 'SV-277133r1148851_rule'
  tag stig_id: 'APPL-26-002180'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-81193r1148850_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe macos_managed_preference('com.apple.applicationaccess', 'allowFindMyDevice') do
    its('value') { should eq false }
  end

  describe macos_managed_preference('com.apple.applicationaccess', 'allowFindMyFriends') do
    its('value') { should eq false }
  end

  describe macos_managed_preference('com.apple.icloud.managed', 'DisableFMMiCloudSetting') do
    its('value') { should eq true }
  end
end
