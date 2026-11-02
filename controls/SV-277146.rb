control 'SV-277146' do
  title 'The macOS system must require a minimum password length of 14 characters.'
  desc 'The macOS must be configured to require that a minimum of 14 characters be used when a password is created.

This rule enforces password complexity by requiring users to set passwords that are less vulnerable to malicious users.

Note: The guidance for password-based authentication in NIST 800-53 (Rev 5) and NIST 800-63B states that complexity rules must be organizationally defined. The values defined are based on common complexity values, but each organization may define its own password complexity rules.'
  desc 'check', %q(Verify the macOS system is configured to enforce a minimum 14-character password length with the following command:

/usr/bin/pwpolicy -getaccountpolicies 2>/dev/null | tail +2 | grep -oE "policyAttributePassword matches '.\{[0-9]+," | awk -F'[{,]' -v ODV=14 '{if ($2 > max) max=$2} END {print (max >= ODV) ? "pass" : "fail"}'

If the result is not "true", this is a finding.)
  desc 'fix', 'Configure the macOS system to enforce a 14-character password length by installing the "com.apple.mobiledevice.passwordpolicy" configuration profile.'
  impact 0.5
  tag check_id: 'C-81301r1149366_chk'
  tag severity: 'medium'
  tag gid: 'V-277146'
  tag rid: 'SV-277146r1149410_rule'
  tag stig_id: 'APPL-26-003010'
  tag gtitle: 'SRG-OS-000078-GPOS-00046'
  tag fix_id: 'F-81206r1148889_fix'
  tag 'documentable'
  tag cci: ['CCI-004066']
  tag nist: ['IA-5 (1) (h)']

  describe macos_pwpolicy do
    its('minimum_length') { should_not be_nil }
    its('minimum_length') { should cmp >= 14 }
  end
end
