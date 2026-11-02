control 'SV-277067' do
  title 'The macOS system must configure audit log files to mode 440 or less permissive.'
  desc 'The audit service must be configured to create log files that are readable only by the root user and group wheel. To achieve this, audit log files must be configured to mode 440 or less permissive to prevent normal users from reading, modifying, or deleting audit logs.

'
  desc 'check', %q(Verify the macOS system is configured with audit log files set to mode 440 or less with the following command:

/bin/ls -l $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '!/-r--r-----|current|total/{print $1}' | /usr/bin/wc -l | /usr/bin/tr -d ' '

If the result is not "0", this is a finding.)
  desc 'fix', 'Configure the macOS system with audit log files set to mode 440 with the following command:

/bin/chmod 440 /var/audit/*'
  impact 0.5
  tag check_id: 'C-81222r1148651_chk'
  tag severity: 'medium'
  tag gid: 'V-277067'
  tag rid: 'SV-277067r1148653_rule'
  tag stig_id: 'APPL-26-001016'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-81127r1148652_fix'
  tag satisfies: ['SRG-OS-000057-GPOS-00027', 'SRG-OS-000058-GPOS-00028', 'SRG-OS-000059-GPOS-00029', 'SRG-OS-000256-GPOS-00097', 'SRG-OS-000257-GPOS-00098', 'SRG-OS-000258-GPOS-00099']
  tag 'documentable'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164', 'CCI-001493', 'CCI-001494', 'CCI-001495']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a', 'AU-9 a', 'AU-9', 'AU-9']
end
