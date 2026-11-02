control 'SV-277036' do
  title 'The macOS system must limit consecutive failed login attempts to three.'
  desc 'The macOS must be configured to limit the number of failed login attempts to a maximum of three. When the maximum number of failed attempts is reached, the account must be locked for a period of time.

This rule protects against malicious users attempting to gain access to the system via brute-force hacking methods.

'
  desc 'check', %q(Verify the macOS system is configured to limit consecutive failed login attempts to three with the following command:

/usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath '//dict/key[text()="policyAttributeMaximumFailedAuthentications"]/following-sibling::integer[1]/text()' - | /usr/bin/awk '{ if ($1 <= 3) {print "pass"} else {print "fail"}}' | /usr/bin/uniq

If the result is not "pass", this is a finding.)
  desc 'fix', 'Configure the macOS system to limit consecutive failed login attempts to three by installing the "com.apple.mobiledevice.passwordpolicy" configuration profile.'
  impact 0.5
  tag check_id: 'C-81191r1149360_chk'
  tag severity: 'medium'
  tag gid: 'V-277036'
  tag rid: 'SV-277036r1149407_rule'
  tag stig_id: 'APPL-26-000022'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag fix_id: 'F-81096r1148559_fix'
  tag satisfies: ['SRG-OS-000021-GPOS-00005', 'SRG-OS-000329-GPOS-00128']
  tag 'documentable'
  tag cci: ['CCI-000044', 'CCI-002238']
  tag nist: ['AC-7 a', 'AC-7 b']
end
