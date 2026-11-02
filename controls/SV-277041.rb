control 'SV-277041' do
  title 'The macOS system must configure the audit log folder to not contain access control lists (ACLs).'
  desc 'The audit log folder must not contain ACLs.

Audit logs contain sensitive data about the system and users. This rule ensures that the audit service is configured to create log folders that are readable and writable only by system administrators to prevent normal users from reading audit logs.

'
  desc 'check', %q(Verify the macOS system is configured without ACLs applied to log folders with the following command:

/bin/ls -lde /var/audit | /usr/bin/awk '{print $1}' | /usr/bin/grep -c ":"

If the result is not "0", this is a finding.)
  desc 'fix', 'Configure the macOS system without ACLs applied to log folders with the following command:

/bin/chmod -N /var/audit'
  impact 0.5
  tag check_id: 'C-81196r1148573_chk'
  tag severity: 'medium'
  tag gid: 'V-277041'
  tag rid: 'SV-277041r1148575_rule'
  tag stig_id: 'APPL-26-000031'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-81101r1148574_fix'
  tag satisfies: ['SRG-OS-000057-GPOS-00027', 'SRG-OS-000058-GPOS-00028', 'SRG-OS-000059-GPOS-00029', 'SRG-OS-000256-GPOS-00097', 'SRG-OS-000257-GPOS-00098', 'SRG-OS-000258-GPOS-00099']
  tag 'documentable'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164', 'CCI-001493', 'CCI-001494', 'CCI-001495']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a', 'AU-9 a', 'AU-9', 'AU-9']
end
