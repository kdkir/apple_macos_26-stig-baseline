control 'SV-277064' do
  title 'The macOS system must configure audit log folders to be owned by root.'
  desc 'Audit log folders must be owned by root.

The audit service must be configured to create log folders with the correct ownership to prevent normal users from reading audit logs.

Audit logs contain sensitive data about the system and users. If log folders are set to be readable and writable only by system administrators, the risk is mitigated.

'
  desc 'check', %q(Verify the macOS system is configured with audit log folders owned by root with the following command:

/bin/ls -dn $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '{print $3}'

If the result is not "0", this is a finding.)
  desc 'fix', 'Configure the macOS system with audit log folders owned by root with the following command:

/usr/sbin/chown root /var/audit'
  impact 0.5
  tag check_id: 'C-81219r1148642_chk'
  tag severity: 'medium'
  tag gid: 'V-277064'
  tag rid: 'SV-277064r1148644_rule'
  tag stig_id: 'APPL-26-001013'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-81124r1148643_fix'
  tag satisfies: ['SRG-OS-000057-GPOS-00027', 'SRG-OS-000058-GPOS-00028', 'SRG-OS-000059-GPOS-00029', 'SRG-OS-000256-GPOS-00097', 'SRG-OS-000257-GPOS-00098', 'SRG-OS-000258-GPOS-00099']
  tag 'documentable'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164', 'CCI-001493', 'CCI-001494', 'CCI-001495']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a', 'AU-9 a', 'AU-9', 'AU-9']
end
