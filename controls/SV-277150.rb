control 'SV-277150' do
  title 'The macOS system must enforce smart card authentication.'
  desc 'Smart card authentication must be enforced.

Using smart card credentials facilitates standardization and reduces the risk of unauthorized access.

When enforceSmartCard is set to "true", the smart card must be used for login, authorization, and unlocking the screen saver.

CAUTION: enforceSmartCard will apply to the whole system. No users will be able to log in with their password unless the profile is removed or a user is exempt from smart card enforcement.

Note: enforceSmartcard requires allowSmartcard to be set to "true" to work.

'
  desc 'check', %q(Verify the macOS system is configured to enforce multifactor authentication with the following command:

/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.security.smartcard')\
.objectForKey('enforceSmartCard').js
EOS

If the result is not "true", this is a finding.)
  desc 'fix', 'Configure the macOS system to enforce multifactor authentication by installing the "com.apple.security.smartcard" configuration profile.

Note: To ensure continued access to the operating system, consult the supplemental guidance provided with the STIG before applying the configuration profile.'
  impact 0.5
  tag check_id: 'C-81305r1148900_chk'
  tag severity: 'medium'
  tag gid: 'V-277150'
  tag rid: 'SV-277150r1148902_rule'
  tag stig_id: 'APPL-26-003020'
  tag gtitle: 'SRG-OS-000067-GPOS-00035'
  tag fix_id: 'F-81210r1148901_fix'
  tag satisfies: ['SRG-OS-000067-GPOS-00035', 'SRG-OS-000105-GPOS-00052', 'SRG-OS-000106-GPOS-00053', 'SRG-OS-000107-GPOS-00054', 'SRG-OS-000108-GPOS-00055', 'SRG-OS-000112-GPOS-00057', 'SRG-OS-000375-GPOS-00160', 'SRG-OS-000376-GPOS-00161', 'SRG-OS-000705-GPOS-00150']
  tag 'documentable'
  tag cci: ['CCI-000186', 'CCI-000765', 'CCI-000766', 'CCI-001941', 'CCI-004046', 'CCI-001953', 'CCI-004047']
  tag nist: ['IA-5 (2) (a) (1)', 'IA-2 (1)', 'IA-2 (2)', 'IA-2 (8)', 'IA-2 (6) (a)', 'IA-2 (12)', 'IA-2 (6) (b)']

  describe macos_managed_preference('com.apple.security.smartcard', 'enforceSmartCard') do
    its('value') { should eq true }
  end
end
