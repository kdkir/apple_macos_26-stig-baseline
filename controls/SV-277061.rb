control 'SV-277061' do
  title 'The macOS system must be configured to audit all login and logout events.'
  desc 'The audit system must be configured to record all attempts to log in and out of the system (lo).

Frequently, an attacker that successfully gains access to a system has only gained access to an account with limited privileges, such as a guest account or service account. The attacker must attempt to change to another user account with normal or elevated privileges to proceed. Auditing both successful and unsuccessful attempts to switch to another user account (by way of monitoring login and logout events) mitigates this risk.

The information system monitors login and logout events.

'
  desc 'check', %q(Verify the macOS system is configured to audit all login and logout events with the following command:

/usr/bin/awk -F':' '/^flags/ { print $NF }' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec '^lo'

If the result is not "1", this is a finding.)
  desc 'fix', %q(Configure the macOS system to audit all login and logout events with the following command:

/usr/bin/grep -qE "^flags.*[^-]lo" /etc/security/audit_control || /usr/bin/sed -i.bak '/^flags/ s/$/,lo/' /etc/security/audit_control; /usr/sbin/audit -s

A text editor may also be used to implement the required updates to the "/etc/security/audit_control" file.)
  impact 0.5
  tag check_id: 'C-81216r1148633_chk'
  tag severity: 'medium'
  tag gid: 'V-277061'
  tag rid: 'SV-277061r1268219_rule'
  tag stig_id: 'APPL-26-001002'
  tag gtitle: 'SRG-OS-000032-GPOS-00013'
  tag fix_id: 'F-81121r1148634_fix'
  tag satisfies: ['SRG-OS-000032-GPOS-00013', 'SRG-OS-000064-GPOS-00033', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000458-GPOS-00203', 'SRG-OS-000470-GPOS-00214', 'SRG-OS-000471-GPOS-00215', 'SRG-OS-000471-GPOS-00216', 'SRG-OS-000472-GPOS-00217', 'SRG-OS-000473-GPOS-00218']
  tag 'documentable'
  tag cci: ['CCI-000067', 'CCI-000172', 'CCI-002884']
  tag nist: ['AC-17 (1)', 'AU-12 c', 'MA-4 (1) (a)']

  describe macos_audit_control do
    its('flags') { should include 'lo' }
  end
end
