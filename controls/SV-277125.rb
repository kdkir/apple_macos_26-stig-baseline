control 'SV-277125' do
  title 'The macOS system must disable TouchID for unlocking the device.'
  desc %q(TouchID enables the ability to unlock a Mac system with a user's fingerprint.

TouchID must be disabled for "Unlocking your Mac" on all macOS devices that are capable of using TouchID.

The system must remain locked until the user establishes access using an authorized identification and authentication method.

Note: TouchID is not an approved biometric authenticator for U.S. federal government use as it has not been verified to meet the strength requirements outlined in NIST SP 800-63.)
  desc 'check', %q(Verify the macOS system is configured to disable TouchID for unlocking the device with the following command:

/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowFingerprintForUnlock').js
EOS

If the result is not "false", this is a finding.)
  desc 'fix', 'Configure the macOS system to disable TouchID for unlocking the device by installing the "com.apple.applicationaccess" configuration profile.'
  impact 0.5
  tag check_id: 'C-81280r1148825_chk'
  tag severity: 'medium'
  tag gid: 'V-277125'
  tag rid: 'SV-277125r1148827_rule'
  tag stig_id: 'APPL-26-002090'
  tag gtitle: 'SRG-OS-000028-GPOS-00009'
  tag fix_id: 'F-81185r1148826_fix'
  tag 'documentable'
  tag cci: ['CCI-000056']
  tag nist: ['AC-11 b']

  describe macos_managed_preference('com.apple.applicationaccess', 'allowFingerprintForUnlock') do
    its('value') { should eq false }
  end
end
