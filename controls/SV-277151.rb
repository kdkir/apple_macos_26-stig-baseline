control 'SV-277151' do
  title 'The macOS system must allow smart card authentication.'
  desc 'Smart card authentication must be allowed.

Using smart card credentials facilitates standardization and reduces the risk of unauthorized access.

When enabled, the smart card can be used for login, authorization, and screen saver unlocking.

'
  desc 'check', %q(Verify the macOS system is configured to allow smart card authentication with the following command:

/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.security.smartcard')\
.objectForKey('allowSmartCard').js
EOS

If the result is not "true", this is a finding.)
  desc 'fix', 'Configure the macOS system to enforce multifactor authentication by installing the "com.apple.security.smartcard" configuration profile.

Note: To ensure continued access to the operating system, consult the supplemental guidance provided with the STIG before applying the configuration profile.'
  impact 0.5
  tag check_id: 'C-81306r1148903_chk'
  tag severity: 'medium'
  tag gid: 'V-277151'
  tag rid: 'SV-277151r1148905_rule'
  tag stig_id: 'APPL-26-003030'
  tag gtitle: 'SRG-OS-000068-GPOS-00036'
  tag fix_id: 'F-81211r1148904_fix'
  tag satisfies: ['SRG-OS-000068-GPOS-00036', 'SRG-OS-000105-GPOS-00052', 'SRG-OS-000106-GPOS-00053', 'SRG-OS-000107-GPOS-00054', 'SRG-OS-000108-GPOS-00055', 'SRG-OS-000112-GPOS-00057', 'SRG-OS-000376-GPOS-00161']
  tag 'documentable'
  tag cci: ['CCI-000187', 'CCI-000765', 'CCI-000766', 'CCI-001941', 'CCI-001953']
  tag nist: ['IA-5 (2) (a) (2)', 'IA-2 (1)', 'IA-2 (2)', 'IA-2 (8)', 'IA-2 (12)']
end
