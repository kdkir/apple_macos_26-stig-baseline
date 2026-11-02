control 'SV-277144' do
  title 'The macOS system must require that passwords contain a minimum of one numeric character.'
  desc 'The macOS must be configured to require at least one numeric character be used when a password is created.

This rule enforces password complexity by requiring users to set passwords that are less vulnerable to malicious users.

Note: The guidance for password-based authentication in NIST 800-53 (Rev 5) and NIST 800-63B states that complexity rules must be organizationally defined. The values defined are based on common complexity values, but each organization may define its own password complexity rules.'
  desc 'check', %q(Verify the macOS system is configured to require that passwords contain a minimum of one numeric character with the following command:

/usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath '//dict/key[text()="policyIdentifier"]/following-sibling::*[1]/text()' - | /usr/bin/grep "requireAlphanumeric" -c

If the result is not "1", this is a finding.)
  desc 'fix', 'Configure the macOS system to require that passwords contain a minimum of one numeric character by installing the "com.apple.mobiledevice.passwordpolicy" configuration profile.'
  impact 0.5
  tag check_id: 'C-81299r1148882_chk'
  tag severity: 'medium'
  tag gid: 'V-277144'
  tag rid: 'SV-277144r1148884_rule'
  tag stig_id: 'APPL-26-003007'
  tag gtitle: 'SRG-OS-000071-GPOS-00039'
  tag fix_id: 'F-81204r1148883_fix'
  tag 'documentable'
  tag cci: ['CCI-004066']
  tag nist: ['IA-5 (1) (h)']

  describe 'pwpolicy identifiers requiring an alphanumeric password' do
    subject { macos_pwpolicy.policy_identifiers.grep(/requireAlphanumeric/) }
    it { should_not be_empty }
  end
end
