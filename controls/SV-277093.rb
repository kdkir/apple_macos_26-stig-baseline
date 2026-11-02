control 'SV-277093' do
  title 'The macOS system must disable FaceTime.app.'
  desc "The macOS built-in FaceTime.app must be disabled.

The FaceTime.app establishes a connection to Apple's iCloud service even when security controls have been put in place to disable iCloud access.

[IMPORTANT]
====
Apple has deprecated the use of application restriction controls (https://github.com/apple/device-management/blob/eb51fb0cb9626cac4717858556912c257a734ce0/mdm/profiles/com.apple.applicationaccess.new.yaml#L67-L70). Using these controls may not work as expected. Third-party software may be required to fulfill the compliance requirements.
===="
  desc 'check', %q(Verify the macOS system is configured to disable FaceTime.app with the following command:

/usr/bin/osascript -l JavaScript << EOS
function run() {
  let pref1 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess.new')\
  .objectForKey('familyControlsEnabled'))
  let pathlist = $.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess.new')\
  .objectForKey('pathBlackList').js
  for ( let app in pathlist ) {
      if ( ObjC.unwrap(pathlist[app]) == "/Applications/FaceTime.app" && pref1 == true ){
          return("true")
      }
  }
  return("false")
  }
EOS

If the result is not "true", this is a finding.)
  desc 'fix', 'Configure the macOS system to disable FaceTime.app by installing the "com.apple.applicationaccess.new" configuration profile.'
  impact 0.5
  tag check_id: 'C-81248r1148729_chk'
  tag severity: 'medium'
  tag gid: 'V-277093'
  tag rid: 'SV-277093r1148731_rule'
  tag stig_id: 'APPL-26-002010'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-81153r1148730_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
