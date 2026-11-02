control 'SV-277075' do
  title 'The macOS system must configure audit capacity warning.'
  desc 'The audit service must be configured to notify the system administrator when the amount of free disk space remaining reaches an organization-defined value.

This rule ensures that the system administrator is notified in advance that action is required to free up more disk space for audit logs.

'
  desc 'check', %q(Verify the macOS system is configured to require a minimum of 25 percent free disk space for audit record storage with the following command:

/usr/bin/awk -F: '/^minfree/{print $2}' /etc/security/audit_control

If the result is not "25", this is a finding.)
  desc 'fix', "Configure the macOS system to require a minimum of 25 percent free disk space for audit record storage with the following command:

/usr/bin/sed -i.bak 's/.*minfree.*/minfree:25/' /etc/security/audit_control; /usr/sbin/audit -s"
  impact 0.5
  tag check_id: 'C-81230r1148675_chk'
  tag severity: 'medium'
  tag gid: 'V-277075'
  tag rid: 'SV-277075r1148677_rule'
  tag stig_id: 'APPL-26-001030'
  tag gtitle: 'SRG-OS-000046-GPOS-00022'
  tag fix_id: 'F-81135r1148676_fix'
  tag satisfies: ['SRG-OS-000046-GPOS-00022', 'SRG-OS-000343-GPOS-00134']
  tag 'documentable'
  tag cci: ['CCI-000139', 'CCI-001855']
  tag nist: ['AU-5 a', 'AU-5 (1)']
end
