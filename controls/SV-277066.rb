control 'SV-277066' do
  title 'The macOS system must configure the audit log folders group to wheel.'
  desc 'Audit log files must have the group set to wheel.

The audit service must be configured to create log files with the correct group ownership to prevent normal users from reading audit logs.

Audit logs contain sensitive data about the system and users. If log files are set to be readable and writable only by system administrators, the risk is mitigated.

'
  desc 'check', %q(Verify the macOS system is configured with audit log folders group-owned by wheel with the following command:

/bin/ls -dn $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '{print $4}'

If the result is not "0", this is a finding.)
  desc 'fix', 'Configure the macOS system with audit log folders group-owned by wheel with the following command:

/usr/bin/chgrp wheel /var/audit'
  impact 0.5
  tag check_id: 'C-81221r1148648_chk'
  tag severity: 'medium'
  tag gid: 'V-277066'
  tag rid: 'SV-277066r1148650_rule'
  tag stig_id: 'APPL-26-001015'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-81126r1148649_fix'
  tag satisfies: ['SRG-OS-000057-GPOS-00027', 'SRG-OS-000058-GPOS-00028', 'SRG-OS-000059-GPOS-00029', 'SRG-OS-000256-GPOS-00097', 'SRG-OS-000257-GPOS-00098', 'SRG-OS-000258-GPOS-00099']
  tag 'documentable'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164', 'CCI-001493', 'CCI-001494', 'CCI-001495']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a', 'AU-9 a', 'AU-9', 'AU-9']
end
