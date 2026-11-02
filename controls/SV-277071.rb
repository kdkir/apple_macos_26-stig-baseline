control 'SV-277071' do
  title 'The macOS system must be configured to audit all failed read actions on the system.'
  desc 'The audit system must be configured to record enforcement actions of access restrictions, including failed file read (-fr) attempts.

Enforcement actions are the methods or mechanisms used to prevent unauthorized access and/or changes to configuration settings. One common and effective enforcement action method is using access restrictions (e.g., denying access to a file by applying file permissions).

This configuration ensures that audit lists include events in which enforcement actions prevent attempts to read a file.

Without auditing the enforcement of access restrictions, it is difficult to identify attempted attacks because no audit trail is available for forensic investigation.

'
  desc 'check', %q(Verify the macOS system is configured to audit all failed read actions on the system with the following command:

/usr/bin/awk -F':' '/^flags/ { print $NF }' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec '\-fr'

If the result is not "1", this is a finding.)
  desc 'fix', %q(Configure the macOS system to audit all failed read actions on the system with the following command:

/usr/bin/grep -qE "^flags.*-fr" /etc/security/audit_control || /usr/bin/sed -i.bak '/^flags/ s/$/,-fr/' /etc/security/audit_control;/usr/sbin/audit -s)
  impact 0.5
  tag check_id: 'C-81226r1148663_chk'
  tag severity: 'medium'
  tag gid: 'V-277071'
  tag rid: 'SV-277071r1148665_rule'
  tag stig_id: 'APPL-26-001022'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-81131r1148664_fix'
  tag satisfies: ['SRG-OS-000057-GPOS-00027', 'SRG-OS-000058-GPOS-00028', 'SRG-OS-000059-GPOS-00029', 'SRG-OS-000064-GPOS-00033', 'SRG-OS-000256-GPOS-00097', 'SRG-OS-000257-GPOS-00098', 'SRG-OS-000258-GPOS-00099', 'SRG-OS-000365-GPOS-00152', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000458-GPOS-00203', 'SRG-OS-000461-GPOS-00205', 'SRG-OS-000463-GPOS-00207', 'SRG-OS-000465-GPOS-00209', 'SRG-OS-000474-GPOS-00219']
  tag 'documentable'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164', 'CCI-000172', 'CCI-001493', 'CCI-001494', 'CCI-001495', 'CCI-003938', 'CCI-002884']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a', 'AU-12 c', 'AU-9 a', 'AU-9', 'AU-9', 'CM-5 (1) (b)', 'MA-4 (1) (a)']
end
