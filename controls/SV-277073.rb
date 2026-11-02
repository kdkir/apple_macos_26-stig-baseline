control 'SV-277073' do
  title 'The macOS system must be configured to audit all failed program execution on the system.'
  desc 'The audit system must be configured to record enforcement actions of access restrictions, including failed program execute (-ex) attempts.

Enforcement actions are the methods or mechanisms used to prevent unauthorized access and/or changes to configuration settings. One common and effective enforcement action method is using program execution restrictions (e.g., denying users access to execute certain processes).

This configuration ensures that audit lists include events in which program execution has failed.

Without auditing the enforcement of program execution, it is difficult to identify attempted attacks because no audit trail is available for forensic investigation.

'
  desc 'check', %q(Verify the macOS system is configured to audit all failed program execution on the system with the following command:

/usr/bin/awk -F':' '/^flags/ { print $NF }' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec '\-ex'

If the result is not "1", this is a finding.)
  desc 'fix', %q(Configure the macOS system to audit all failed program execution on the system with the following command:

/usr/bin/grep -qE "^flags.*-ex" /etc/security/audit_control || /usr/bin/sed -i.bak '/^flags/ s/$/,-ex/' /etc/security/audit_control; /usr/sbin/audit -s)
  impact 0.5
  tag check_id: 'C-81228r1148669_chk'
  tag severity: 'medium'
  tag gid: 'V-277073'
  tag rid: 'SV-277073r1148671_rule'
  tag stig_id: 'APPL-26-001024'
  tag gtitle: 'SRG-OS-000365-GPOS-00152'
  tag fix_id: 'F-81133r1148670_fix'
  tag satisfies: ['SRG-OS-000365-GPOS-00152', 'SRG-OS-000458-GPOS-00203', 'SRG-OS-000463-GPOS-00207', 'SRG-OS-000465-GPOS-00209']
  tag 'documentable'
  tag cci: ['CCI-003938', 'CCI-000172']
  tag nist: ['CM-5 (1) (b)', 'AU-12 c']

  describe macos_audit_control do
    its('flags') { should include '-ex' }
  end
end
