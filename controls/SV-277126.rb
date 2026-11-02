control 'SV-277126' do
  title 'The macOS system must disable Media Sharing.'
  desc %q(Media Sharing must be disabled.

When Media Sharing is enabled, the computer starts a network listening service that shares the contents of the user's music collection with other users in the same subnet.

The information system must be configured to provide only essential capabilities. Disabling Media Sharing helps prevent the unauthorized connection of devices and unauthorized transfer of information. Disabling Media Sharing mitigates this risk.

Note: The Media Sharing preference panel will still allow "Home Sharing" and "Share media with guests" to be checked, but the service will not be enabled.)
  desc 'check', %q(Verify the macOS system is configured to disable Media Sharing with the following commands:

/usr/bin/osascript -l JavaScript << EOS
function run() {
let pref1 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowMediaSharing'))
let pref2 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowMediaSharingModification'))
if ( pref1 == false && pref2 == false ) {
return("true")
} else {
return("false")
}
}
EOS

If the result is not "true", this is a finding.)
  desc 'fix', 'Configure the macOS system to disable Media Sharing by installing the "com.apple.applicationaccess" configuration profile.'
  impact 0.5
  tag check_id: 'C-81281r1148828_chk'
  tag severity: 'medium'
  tag gid: 'V-277126'
  tag rid: 'SV-277126r1268226_rule'
  tag stig_id: 'APPL-26-002100'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-81186r1148829_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']

  describe macos_managed_preference('com.apple.applicationaccess', 'allowMediaSharing') do
    its('value') { should eq false }
  end

  describe macos_managed_preference('com.apple.applicationaccess', 'allowMediaSharingModification') do
    its('value') { should eq false }
  end
end
