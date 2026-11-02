control 'SV-277060' do
  title 'The macOS system must be configured to audit all administrative action events.'
  desc 'The auditing system must be configured to flag administrative action (ad) events.

Administrative action events include changes made to the system (e.g., modifying authentication policies). If audit records do not include ad events, it is difficult to identify incidents and to correlate incidents to subsequent events.

Audit records can be generated from various components within the information system (e.g., via a module or policy filter).

The information system audits the execution of privileged functions.

Note: Changing the line "43127:AUE_MAC_SYSCALL:mac_syscall(2):ad" to "43127:AUE_MAC_SYSCALL:mac_syscall(2):zz" in the file /etc/security/audit_event is recommended. This will prevent sandbox violations from being audited by the ad flag.

'
  desc 'check', %q(Verify the macOS system is configured to audit privileged access with the following command:

/usr/bin/awk -F':' '/^flags/ { print $NF }' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec 'ad'

If the result is not "1", this is a finding.)
  desc 'fix', %q(Configure the macOS system to audit privileged access with the following command:

/usr/bin/grep -qE "^flags.*[^-]ad" /etc/security/audit_control || /usr/bin/sed -i.bak '/^flags/ s/$/,ad/' /etc/security/audit_control; /usr/sbin/audit -s

A text editor may also be used to implement the required updates to the "/etc/security/audit_control" file.)
  impact 0.5
  tag check_id: 'C-81215r1148630_chk'
  tag severity: 'medium'
  tag gid: 'V-277060'
  tag rid: 'SV-277060r1148632_rule'
  tag stig_id: 'APPL-26-001001'
  tag gtitle: 'SRG-OS-000004-GPOS-00004'
  tag fix_id: 'F-81120r1148631_fix'
  tag satisfies: ['SRG-OS-000004-GPOS-00004', 'SRG-OS-000239-GPOS-00089', 'SRG-OS-000240-GPOS-00090', 'SRG-OS-000241-GPOS-00091', 'SRG-OS-000303-GPOS-00120', 'SRG-OS-000327-GPOS-00127', 'SRG-OS-000365-GPOS-00152', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000458-GPOS-00203', 'SRG-OS-000471-GPOS-00215', 'SRG-OS-000471-GPOS-00216', 'SRG-OS-000476-GPOS-00221']
  tag 'documentable'
  tag cci: ['CCI-000018', 'CCI-001403', 'CCI-001404', 'CCI-001405', 'CCI-002130', 'CCI-002234', 'CCI-003938', 'CCI-002884', 'CCI-000172']
  tag nist: ['AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)', 'AC-6 (9)', 'CM-5 (1) (b)', 'MA-4 (1) (a)', 'AU-12 c']

  describe macos_audit_control do
    its('flags') { should include 'ad' }
  end
end
