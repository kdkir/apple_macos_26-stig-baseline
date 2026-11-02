control 'SV-277028' do
  title 'The macOS system must prevent Apple Watch from terminating a session lock.'
  desc 'Apple Watches are not an approved authenticator and their use must be disabled.

Disabling Apple Watches is a necessary step to ensuring that the information system retains a session lock until the user reestablishes access using an authorized identification and authentication procedures.

Note: Unlocking the system with an Apple Watch is not an approved authenticator for U.S. federal government usage as it has not been verified to meet the strength requirements outlined in NIST SP 800-63.'
  desc 'check', %q(Verify the macOS system is configured to prevent Apple Watch from terminating a session lock with the following command:

/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowAutoUnlock').js
EOS

If the result is not "false", this is a finding.)
  desc 'fix', 'Configure the macOS system to prevent Apple Watch from terminating a session lock by installing the "com.apple.applicationaccess" configuration profile.'
  impact 0.5
  tag check_id: 'C-81183r1148534_chk'
  tag severity: 'medium'
  tag gid: 'V-277028'
  tag rid: 'SV-277028r1148536_rule'
  tag stig_id: 'APPL-26-000001'
  tag gtitle: 'SRG-OS-000028-GPOS-00009'
  tag fix_id: 'F-81088r1148535_fix'
  tag 'documentable'
  tag cci: ['CCI-000056']
  tag nist: ['AC-11 b']
end
