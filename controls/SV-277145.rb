control 'SV-277145' do
  title 'The macOS system must restrict maximum password lifetime to 180 days.'
  desc 'The macOS must be configured to enforce a maximum password lifetime limit of at least 180 days.

This rule ensures that users are forced to change their passwords frequently enough to prevent malicious users from gaining and maintaining access to the system.

Note: The guidance for password-based authentication in NIST 800-53 (Rev 5) and NIST 800-63B states that complexity rules must be organizationally defined. The values defined are based on common complexity values, but each organization may define its own password complexity rules.'
  desc 'check', %q(Verify the macOS system is configured to restrict maximum password lifetime to 180 days with the following command:

/usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath '//dict/key[text()="policyAttributeExpiresEveryNDays"]/following-sibling::*[1]/text()' - | /usr/bin/awk '{ if ($1 <= 180 ) {print "pass"} else {print "fail"}}' | /usr/bin/uniq

If the result is not "pass" or fewer, this is a finding.)
  desc 'fix', 'Configure the macOS system to restrict maximum password lifetime to 180 days by installing the "com.apple.mobiledevice.passwordpolicy" configuration profile.'
  impact 0.5
  tag check_id: 'C-81300r1268020_chk'
  tag severity: 'medium'
  tag gid: 'V-277145'
  tag rid: 'SV-277145r1268211_rule'
  tag stig_id: 'APPL-26-003008'
  tag gtitle: 'SRG-OS-000076-GPOS-00044'
  tag fix_id: 'F-81205r1268021_fix'
  tag 'documentable'
  tag cci: ['CCI-004066']
  tag nist: ['IA-5 (1) (h)']
end
