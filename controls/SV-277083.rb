control 'SV-277083' do
  title 'The macOS system must configure audit_control to not contain access control lists (ACLs).'
  desc '/etc/security/audit_control must not contain ACLs.

/etc/security/audit_control contains sensitive configuration data about the audit service. This rule ensures that the audit service is configured to be readable and writable only by system administrators to prevent normal users from manipulating audit logs.

'
  desc 'check', %q(Verify the macOS system is configured without ACLs applied to audit_control with the following command:

/bin/ls -le /etc/security/audit_control | /usr/bin/awk '{print $1}' | /usr/bin/grep -c ":"

If the result is not "0", this is a finding.)
  desc 'fix', 'Configure the macOS system without ACLs applied to audit_control with the following command:

/bin/chmod -N /etc/security/audit_control'
  impact 0.5
  tag check_id: 'C-81238r1148699_chk'
  tag severity: 'medium'
  tag gid: 'V-277083'
  tag rid: 'SV-277083r1148701_rule'
  tag stig_id: 'APPL-26-001140'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-81143r1148700_fix'
  tag satisfies: ['SRG-OS-000057-GPOS-00027', 'SRG-OS-000058-GPOS-00028', 'SRG-OS-000059-GPOS-00029', 'SRG-OS-000063-GPOS-00032', 'SRG-OS-000256-GPOS-00097', 'SRG-OS-000257-GPOS-00098', 'SRG-OS-000258-GPOS-00099']
  tag 'documentable'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164', 'CCI-000171', 'CCI-001493', 'CCI-001494', 'CCI-001495']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a', 'AU-12 b', 'AU-9 a', 'AU-9', 'AU-9']
end
