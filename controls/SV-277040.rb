control 'SV-277040' do
  title 'The macOS system must configure audit log files to not contain access control lists (ACLs).'
  desc 'The audit log files must not contain ACLs.

This rule ensures that audit information and audit files are configured to be readable and writable only by system administrators, thereby preventing unauthorized access, modification, and deletion of files.

'
  desc 'check', %q(Verify the macOS system is configured without ACLs applied to log files with the following command:

/bin/ls -le $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '{print $1}' | /usr/bin/grep -c ":"

If the result is not "0", this is a finding.)
  desc 'fix', 'Configure the macOS system without ACLs applied to log files with the following command:

/bin/chmod -RN /var/audit'
  impact 0.5
  tag check_id: 'C-81195r1148570_chk'
  tag severity: 'medium'
  tag gid: 'V-277040'
  tag rid: 'SV-277040r1148572_rule'
  tag stig_id: 'APPL-26-000030'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-81100r1148571_fix'
  tag satisfies: ['SRG-OS-000057-GPOS-00027', 'SRG-OS-000058-GPOS-00028', 'SRG-OS-000059-GPOS-00029', 'SRG-OS-000256-GPOS-00097', 'SRG-OS-000257-GPOS-00098', 'SRG-OS-000258-GPOS-00099']
  tag 'documentable'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164', 'CCI-001493', 'CCI-001494', 'CCI-001495']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a', 'AU-9 a', 'AU-9', 'AU-9']

  audit_dir = macos_audit_control.dir

  describe 'The audit log directory configured in /etc/security/audit_control' do
    subject { audit_dir }
    it { should_not be_nil }
  end

  if audit_dir
    describe "ACL entries on audit log files in #{audit_dir}" do
      subject { command("/bin/ls -le #{audit_dir}").stdout.lines.map(&:strip).grep(/\A\d+: /) }
      it { should be_empty }
    end
  end
end
