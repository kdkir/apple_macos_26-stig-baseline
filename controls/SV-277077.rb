control 'SV-277077' do
  title 'The macOS system must be configured to audit all authorization and authentication events.'
  desc 'The auditing system must be configured to flag authorization and authentication (aa) events.

Authentication events contain information about the identity of a user, server, or client. Authorization events contain information about permissions, rights, and rules. If audit records do not include aa events, it is difficult to identify incidents and correlate incidents to subsequent events.

Audit records can be generated from various components within the information system (e.g., via a module or policy filter).

'
  desc 'check', %q(Verify the macOS system is configured to audit login events with the following command:

/usr/bin/awk -F':' '/^flags/ { print $NF }' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec 'aa'

If the result is not "1", this is a finding.)
  desc 'fix', %q(Configure the macOS system to audit login events with the following command:

/usr/bin/grep -qE "^flags.*[^-]aa" /etc/security/audit_control || /usr/bin/sed -i.bak '/^flags/ s/$/,aa/' /etc/security/audit_control; /usr/sbin/audit -s)
  impact 0.5
  tag check_id: 'C-81232r1148681_chk'
  tag severity: 'medium'
  tag gid: 'V-277077'
  tag rid: 'SV-277077r1148683_rule'
  tag stig_id: 'APPL-26-001044'
  tag gtitle: 'SRG-OS-000365-GPOS-00152'
  tag fix_id: 'F-81137r1148682_fix'
  tag satisfies: ['SRG-OS-000365-GPOS-00152', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000458-GPOS-00203', 'SRG-OS-000463-GPOS-00207', 'SRG-OS-000465-GPOS-00209', 'SRG-OS-000466-GPOS-00210', 'SRG-OS-000467-GPOS-00211', 'SRG-OS-000468-GPOS-00212', 'SRG-OS-000471-GPOS-00215', 'SRG-OS-000471-GPOS-00216', 'SRG-OS-000475-GPOS-00220', 'SRG-OS-000477-GPOS-00222']
  tag 'documentable'
  tag cci: ['CCI-003938', 'CCI-002884', 'CCI-000172']
  tag nist: ['CM-5 (1) (b)', 'MA-4 (1) (a)', 'AU-12 c']

  describe macos_audit_control do
    its('flags') { should include 'aa' }
  end
end
