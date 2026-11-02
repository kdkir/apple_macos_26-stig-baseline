control 'SV-277074' do
  title 'The macOS system must configure audit retention to seven days.'
  desc 'The audit service must be configured to require that records be kept for an organizational-defined value before deletion unless the system uses a central audit record storage facility.

When "expire-after" is set to "7d", the audit service will not delete audit logs until the log data criteria is met.'
  desc 'check', %q(Verify the macOS system is configured to set audit retention to seven days with the following command:

/usr/bin/awk -F: '/expire-after/{print $2}' /etc/security/audit_control

If the result is not "7d", this is a finding.)
  desc 'fix', "Configure the macOS system to set audit retention to seven days with the following command:

/usr/bin/sed -i.bak 's/^expire-after.*/expire-after:7d/' /etc/security/audit_control; /usr/sbin/audit -s"
  impact 0.3
  tag check_id: 'C-81229r1148672_chk'
  tag severity: 'low'
  tag gid: 'V-277074'
  tag rid: 'SV-277074r1148674_rule'
  tag stig_id: 'APPL-26-001029'
  tag gtitle: 'SRG-OS-000341-GPOS-00132'
  tag fix_id: 'F-81134r1148673_fix'
  tag 'documentable'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']

  describe macos_audit_control do
    its('expire_after') { should cmp '7d' }
  end
end
