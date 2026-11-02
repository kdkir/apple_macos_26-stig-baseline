control 'SV-277155' do
  title 'The macOS system must require that passwords contain a minimum of one lowercase character and one uppercase character.'
  desc 'The macOS must be configured to require at least one lowercase character and one uppercase character be used when a password is created.

This rule enforces password complexity by requiring users to set passwords that are less vulnerable to malicious users.

Note: The guidance for password-based authentication in NIST 800-53 (Rev 5) and NIST 800-63B states that complexity rules must be organizationally defined. The values defined are based on common complexity values, but each organization may define its own password complexity rules.

Note: The configuration profile generated must be installed from a Mobile Device Management (MDM) server.

'
  desc 'check', %q(Verify the macOS system is configured to require that passwords contain a minimum of one lowercase character and one uppercase character with the following command:

/usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath 'boolean(//*[contains(text(),"policyAttributePassword matches '\''^(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9]).*$'\''")])' -

If the result is not "true", this is a finding.)
  desc 'fix', 'Configure the macOS system to require at least one lowercase character and one uppercase character in password complexity by installing the "com.apple.mobiledevice.passwordpolicy" configuration profile.'
  impact 0.5
  tag check_id: 'C-81310r1148915_chk'
  tag severity: 'medium'
  tag gid: 'V-277155'
  tag rid: 'SV-277155r1148917_rule'
  tag stig_id: 'APPL-26-003060'
  tag gtitle: 'SRG-OS-000069-GPOS-00037'
  tag fix_id: 'F-81215r1148916_fix'
  tag satisfies: ['SRG-OS-000069-GPOS-00037', 'SRG-OS-000070-GPOS-00038', 'SRG-OS-000730-GPOS-00190']
  tag 'documentable'
  tag cci: ['CCI-004066', 'CCI-004065']
  tag nist: ['IA-5 (1) (h)', 'IA-5 (1) (g)']
end
