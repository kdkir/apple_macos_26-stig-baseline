control 'SV-277177' do
  title 'The macOS system must authorize USB devices before allowing connection.'
  desc 'USB devices connected to a Mac must be authorized.

[IMPORTANT]
====
This feature is removed if a smart card is paired or smart card attribute mapping is configured.
====

Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity.

'
  desc 'check', %q(Verify the macOS system is configured to authorize USB devices before allowing connection with the following command:

/usr/bin/osascript -l JavaScript << EOS
function run() {
let pref1 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowUSBRestrictedMode'))
if ( pref1 == false ) {
return("false")
} else {
return("true")
}
}
EOS

If the result is not "true", this is a finding.)
  desc 'fix', 'Configure the macOS system to authorize USB devices before allowing connection by installing the "com.apple.applicationaccess" configuration profile.'
  impact 0.5
  tag check_id: 'C-81332r1148981_chk'
  tag severity: 'medium'
  tag gid: 'V-277177'
  tag rid: 'SV-277177r1148983_rule'
  tag stig_id: 'APPL-26-005090'
  tag gtitle: 'SRG-OS-000378-GPOS-00163'
  tag fix_id: 'F-81237r1148982_fix'
  tag satisfies: ['SRG-OS-000378-GPOS-00163', 'SRG-OS-000690-GPOS-00140']
  tag 'documentable'
  tag cci: ['CCI-001958', 'CCI-003959']
  tag nist: ['IA-3', 'CM-7 (9) (b)']

  describe macos_managed_preference('com.apple.applicationaccess', 'allowUSBRestrictedMode') do
    its('value') { should_not eq false }
  end
end
