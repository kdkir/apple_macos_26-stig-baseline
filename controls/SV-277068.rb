control 'SV-277068' do
  title 'The macOS system must configure audit log folders to mode 700 or less permissive.'
  desc 'The audit log folder must be configured to mode 700 or less permissive so that only the root user is able to read, write, and execute changes to folders.

Because audit logs contain sensitive data about the system and users, the audit service must be configured to mode 700 or less permissive to prevent normal users from reading, modifying or deleting audit logs.

'
  desc 'check', "Verify the macOS system is configured with audit log folders set to mode 700 or less permissive with the following command:

/usr/bin/stat -f %A $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}')

If the result is not a mode of 700 or less permissive, this is a finding."
  desc 'fix', 'Configure the macOS system with audit log folders set to mode 700 with the following command:

/bin/chmod 700 /var/audit'
  impact 0.5
  tag check_id: 'C-81223r1148654_chk'
  tag severity: 'medium'
  tag gid: 'V-277068'
  tag rid: 'SV-277068r1148656_rule'
  tag stig_id: 'APPL-26-001017'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-81128r1148655_fix'
  tag satisfies: ['SRG-OS-000057-GPOS-00027', 'SRG-OS-000058-GPOS-00028', 'SRG-OS-000059-GPOS-00029', 'SRG-OS-000256-GPOS-00097', 'SRG-OS-000257-GPOS-00098', 'SRG-OS-000258-GPOS-00099']
  tag 'documentable'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164', 'CCI-001493', 'CCI-001494', 'CCI-001495']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a', 'AU-9 a', 'AU-9', 'AU-9']
end
