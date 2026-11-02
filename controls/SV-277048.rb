control 'SV-277048' do
  title 'The macOS system must set account lockout time to 15 minutes.'
  desc 'The macOS system must be configured to enforce a lockout time of at least 15 minutes when the maximum number of failed login attempts is reached.

This rule protects against malicious users attempting to gain access to the system via brute-force hacking methods.

'
  desc 'check', %q(Verify the macOS system is configured to set account lockout time to 15 minutes with the following command:

/usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath '//dict/key[text()="autoEnableInSeconds"]/following-sibling::integer[1]/text()' - | /usr/bin/awk '{ if ($1/60 >= 15 ) {print "pass"} else {print "fail"}}' | /usr/bin/uniq

If the result is not "pass", this is a finding.)
  desc 'fix', 'Configure the macOS system to set account lockout time to 15 minutes by installing the "com.apple.mobiledevice.passwordpolicy" configuration profile.'
  impact 0.5
  tag check_id: 'C-81203r1149362_chk'
  tag severity: 'medium'
  tag gid: 'V-277048'
  tag rid: 'SV-277048r1149408_rule'
  tag stig_id: 'APPL-26-000060'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag fix_id: 'F-81108r1148595_fix'
  tag satisfies: ['SRG-OS-000021-GPOS-00005', 'SRG-OS-000329-GPOS-00128']
  tag 'documentable'
  tag cci: ['CCI-000044', 'CCI-002238']
  tag nist: ['AC-7 a', 'AC-7 b']
end
