control 'SV-277063' do
  title 'The macOS system must configure audit log files to be owned by root.'
  desc 'Audit log files must be owned by root.

The audit service must be configured to create log files with the correct ownership to prevent normal users from reading audit logs.

Audit logs contain sensitive data about the system and users. If log files are set to be readable and writable only by system administrators, the risk is mitigated.

'
  desc 'check', %q(Verify the macOS system is configured with audit log files owned by root with the following command:

/bin/ls -n $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '{s+=$3} END {print s}'

If the result is not "0", this is a finding.)
  desc 'fix', 'Configure the macOS system with audit log files owned by root with the following command:

/usr/sbin/chown -R root /var/audit/*'
  impact 0.5
  tag check_id: 'C-81218r1148639_chk'
  tag severity: 'medium'
  tag gid: 'V-277063'
  tag rid: 'SV-277063r1148641_rule'
  tag stig_id: 'APPL-26-001012'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-81123r1148640_fix'
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
    offenders = macos_file_stats(dir: audit_dir).entries.reject { |e| e.owner == 'root' }.map(&:path)

    describe "Audit log files in #{audit_dir} not owned by root" do
      subject { offenders }
      it { should be_empty }
    end
  end
end
