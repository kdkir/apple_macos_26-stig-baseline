control 'SV-277081' do
  title 'The macOS system must configure audit_control owner to root.'
  desc '/etc/security/audit_control must have the owner set to root.

The audit service must be configured with the correct ownership to prevent normal users from manipulating audit log configurations.

'
  desc 'check', %q(Verify the macOS system is configured with the audit_control owner to root with the following command:

/bin/ls -dn /etc/security/audit_control | /usr/bin/awk '{print $3}'

If the result is not "0", this is a finding.)
  desc 'fix', 'Configure the macOS system with the audit_control owner to root with the following command:

/usr/sbin/chown root /etc/security/audit_control'
  impact 0.5
  tag check_id: 'C-81236r1148693_chk'
  tag severity: 'medium'
  tag gid: 'V-277081'
  tag rid: 'SV-277081r1148695_rule'
  tag stig_id: 'APPL-26-001120'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-81141r1148694_fix'
  tag satisfies: ['SRG-OS-000057-GPOS-00027', 'SRG-OS-000058-GPOS-00028', 'SRG-OS-000059-GPOS-00029', 'SRG-OS-000063-GPOS-00032', 'SRG-OS-000256-GPOS-00097', 'SRG-OS-000257-GPOS-00098', 'SRG-OS-000258-GPOS-00099']
  tag 'documentable'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164', 'CCI-000171', 'CCI-001493', 'CCI-001494', 'CCI-001495']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a', 'AU-12 b', 'AU-9 a', 'AU-9', 'AU-9']

  describe file('/etc/security/audit_control') do
    it { should exist }
    its('owner') { should cmp 'root' }
  end
end
