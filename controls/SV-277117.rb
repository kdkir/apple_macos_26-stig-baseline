control 'SV-277117' do
  title 'The macOS system must apply gatekeeper settings to block applications from unidentified developers.'
  desc 'The information system implements cryptographic mechanisms to authenticate software prior to installation.

Gatekeeper settings must be configured correctly to allow the system to run only applications downloaded from the Mac App Store or applications signed with a valid Apple Developer ID code. Administrator users will still have the option to override these settings on a per-app basis. Gatekeeper is a security feature that ensures that applications must be digitally signed by an Apple-issued certificate to run. Digital signatures allow the macOS to verify that the application has not been modified by a malicious third party.'
  desc 'check', %q(Verify the macOS system is configured to apply gatekeeper settings to block applications from unidentified developers with the following commands:

/usr/bin/osascript -l JavaScript << EOS
function run() {
let pref1 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.systempolicy.control')\
.objectForKey('AllowIdentifiedDevelopers'))
let pref2 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.systempolicy.control')\
.objectForKey('EnableAssessment'))
if ( pref1 == true && pref2 == true ) {
return("true")
} else {
return("false")
}
}
EOS

If the result is not "true", this is a finding.)
  desc 'fix', 'Configure the macOS system to apply gatekeeper settings to block applications from unidentified developers by installing the "com.apple.systempolicy.control" configuration profile.'
  impact 0.7
  tag check_id: 'C-81272r1148801_chk'
  tag severity: 'high'
  tag gid: 'V-277117'
  tag rid: 'SV-277117r1268241_rule'
  tag stig_id: 'APPL-26-002060'
  tag gtitle: 'SRG-OS-000366-GPOS-00153'
  tag fix_id: 'F-81177r1148802_fix'
  tag 'documentable'
  tag cci: ['CCI-003992']
  tag nist: ['CM-14']

  describe macos_managed_preference('com.apple.systempolicy.control', 'AllowIdentifiedDevelopers') do
    its('value') { should eq true }
  end

  describe macos_managed_preference('com.apple.systempolicy.control', 'EnableAssessment') do
    its('value') { should eq true }
  end
end
