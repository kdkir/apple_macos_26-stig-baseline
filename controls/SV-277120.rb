control 'SV-277120' do
  title 'The macOS system must enable gatekeeper.'
  desc 'Gatekeeper must be enabled.

Gatekeeper is a security feature that ensures that applications are digitally signed by an Apple-issued certificate before they are permitted to run. Digital signatures allow the macOS host to verify the application has not been modified by a malicious third party.

Administrator users will still have the option to override these settings on a case-by-case basis.'
  desc 'check', %q(Verify the macOS system is configured to enable gatekeeper with the following command:

/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.systempolicy.control')\
.objectForKey('EnableAssessment').js
EOS

If the result is not "true", this is a finding.)
  desc 'fix', 'Configure the macOS system to enable gatekeeper by installing the "com.apple.systempolicy.control" configuration profile.'
  impact 0.7
  tag check_id: 'C-81275r1148810_chk'
  tag severity: 'high'
  tag gid: 'V-277120'
  tag rid: 'SV-277120r1268241_rule'
  tag stig_id: 'APPL-26-002064'
  tag gtitle: 'SRG-OS-000366-GPOS-00153'
  tag fix_id: 'F-81180r1148811_fix'
  tag 'documentable'
  tag cci: ['CCI-003992']
  tag nist: ['CM-14']
end
