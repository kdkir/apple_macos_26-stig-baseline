control 'SV-277065' do
  title 'The macOS system must configure the audit log files group to wheel.'
  desc 'Audit log files must have the group set to wheel.

The audit service must be configured to create log files with the correct group ownership to prevent normal users from reading audit logs.

Audit logs contain sensitive data about the system and users. If log files are set to be readable and writable only by system administrators, the risk is mitigated.

'
  desc 'check', %q(Verify the macOS system is configured with audit log files group-owned by wheel with the following command:

/bin/ls -n $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '{s+=$4} END {print s}'

If the result is not "0", this is a finding.)
  desc 'fix', 'Configure the macOS system with audit log files group-owned by wheel with the following command:

/usr/bin/chgrp -R wheel /var/audit/*'
  impact 0.5
  tag check_id: 'C-81220r1148645_chk'
  tag severity: 'medium'
  tag gid: 'V-277065'
  tag rid: 'SV-277065r1148647_rule'
  tag stig_id: 'APPL-26-001014'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-81125r1148646_fix'
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
    offenders = macos_file_stats(dir: audit_dir).entries.reject { |e| e.group == 'wheel' }.map(&:path)

    describe "Audit log files in #{audit_dir} not group-owned by wheel" do
      subject { offenders }
      it { should be_empty }
    end
  end
end
