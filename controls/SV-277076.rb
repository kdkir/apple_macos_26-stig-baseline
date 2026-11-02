control 'SV-277076' do
  title 'The macOS system must configure audit failure notification.'
  desc "The audit service must be configured to immediately print messages to the console or email administrator users when an auditing failure occurs.

It is critical for the appropriate personnel to be made aware immediately if a system is at risk of failing to process audit logs as required. Without a real-time alert, security personnel may be unaware of a potentially harmful failure in the auditing system's capability, and system operation may be adversely affected."
  desc 'check', 'Verify the macOS system is configured to produce audit failure notification with the following command:

/usr/bin/grep -c "logger -s -p" /etc/security/audit_warn

If the result is not "1", this is a finding.'
  desc 'fix', "Configure the macOS system to produce audit failure notification with the following command:

/usr/bin/sed -i.bak 's/logger -p/logger -s -p/' /etc/security/audit_warn; /usr/sbin/audit -s"
  impact 0.5
  tag check_id: 'C-81231r1148678_chk'
  tag severity: 'medium'
  tag gid: 'V-277076'
  tag rid: 'SV-277076r1148680_rule'
  tag stig_id: 'APPL-26-001031'
  tag gtitle: 'SRG-OS-000344-GPOS-00135'
  tag fix_id: 'F-81136r1148679_fix'
  tag 'documentable'
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']
end
