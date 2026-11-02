control 'SV-277147' do
  title 'The macOS system must require that passwords contain a minimum of one special character.'
  desc 'The macOS must be configured to require that at least one special character be used when a password is created.

Special characters are characters that are not alphanumeric. Examples include: ~ ! @ # $ % ^ *.

This rule enforces password complexity by requiring users to set passwords that are less vulnerable to malicious users.

Note: The guidance for password-based authentication in NIST 800-53 (Rev 5) and NIST 800-63B states that complexity rules must be organizationally defined. The values defined are based on common complexity values, but each organization may define its own password complexity rules.'
  desc 'check', %q(Verify the macOS system is configured to require passwords contain a minimum of one special character with the following command:

/usr/bin/pwpolicy -getaccountpolicies 2>/dev/null | /usr/bin/tail -n +2 | /usr/bin/xmllint --xpath "//string[contains(text(), \"policyAttributePassword matches '(.*[^a-zA-Z0-9].*){\")]" - 2>/dev/null | /usr/bin/awk -F"{|}" '{if ($2 >= 1) {print "pass"} else {print "fail"}}'

If the result is not "pass", this is a finding.)
  desc 'fix', 'Configure the macOS system to require that passwords contain a minimum of one special character by installing the "com.apple.mobiledevice.passwordpolicy" configuration profile.'
  impact 0.5
  tag check_id: 'C-81302r1149368_chk'
  tag severity: 'medium'
  tag gid: 'V-277147'
  tag rid: 'SV-277147r1149411_rule'
  tag stig_id: 'APPL-26-003011'
  tag gtitle: 'SRG-OS-000266-GPOS-00101'
  tag fix_id: 'F-81207r1148892_fix'
  tag 'documentable'
  tag cci: ['CCI-004066']
  tag nist: ['IA-5 (1) (h)']
end
