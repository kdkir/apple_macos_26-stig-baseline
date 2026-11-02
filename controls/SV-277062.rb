control 'SV-277062' do
  title 'The macOS system must enable security auditing.'
  desc "The information system must be configured to generate audit records.

Audit records establish what types of events have occurred, when they occurred, and which users were involved. These records aid an organization in their efforts to establish, correlate, and investigate the events leading up to an outage or attack.

The content required to be captured in an audit record varies based on the impact level of an organization's system. Content that may be necessary to satisfy this requirement includes, for example, time stamps, source addresses, destination addresses, user identifiers, event descriptions, success/fail indications, filenames involved, and access or flow control rules invoked.

The information system initiates session audits at system startup.

Note: Security auditing is NOT enabled by default on macOS Tahoe.

"
  desc 'check', %q(Verify the macOS system is configured to enable the auditd service with the following command:

LAUNCHD_RUNNING=$(/bin/launchctl print system | /usr/bin/grep -c -E '\tcom.apple.auditd')
AUDITD_RUNNING=$(/usr/sbin/audit -c | /usr/bin/grep -c "AUC_AUDITING")
if [[ $LAUNCHD_RUNNING == 1 ]] && [[ -e /etc/security/audit_control ]] && [[ $AUDITD_RUNNING == 1 ]]; then
  echo "pass"
else
  echo "fail"
fi

If the result is not "pass", this is a finding.)
  desc 'fix', 'Configure the macOS system to enable the auditd service with the following command:

if [[ ! -e /etc/security/audit_control ]] && [[ -e /etc/security/audit_control.example ]];then
  /bin/cp /etc/security/audit_control.example /etc/security/audit_control
fi

/bin/launchctl enable system/com.apple.auditd
/bin/launchctl bootstrap system /System/Library/LaunchDaemons/com.apple.auditd.plist
/usr/sbin/audit -i'
  impact 0.5
  tag check_id: 'C-81217r1149356_chk'
  tag severity: 'medium'
  tag gid: 'V-277062'
  tag rid: 'SV-277062r1149405_rule'
  tag stig_id: 'APPL-26-001003'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag fix_id: 'F-81122r1148637_fix'
  tag satisfies: ['SRG-OS-000037-GPOS-00015', 'SRG-OS-000038-GPOS-00016', 'SRG-OS-000039-GPOS-00017', 'SRG-OS-000040-GPOS-00018', 'SRG-OS-000041-GPOS-00019', 'SRG-OS-000042-GPOS-00020', 'SRG-OS-000042-GPOS-00021', 'SRG-OS-000055-GPOS-00026', 'SRG-OS-000254-GPOS-00095', 'SRG-OS-000255-GPOS-00096', 'SRG-OS-000257-GPOS-00098', 'SRG-OS-000258-GPOS-00099', 'SRG-OS-000337-GPOS-00129', 'SRG-OS-000358-GPOS-00145', 'SRG-OS-000359-GPOS-00146', 'SRG-OS-000365-GPOS-00152', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000458-GPOS-00203', 'SRG-OS-000461-GPOS-00205', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000463-GPOS-00207', 'SRG-OS-000465-GPOS-00209', 'SRG-OS-000466-GPOS-00210', 'SRG-OS-000467-GPOS-00211', 'SRG-OS-000468-GPOS-00212', 'SRG-OS-000470-GPOS-00214', 'SRG-OS-000471-GPOS-00215', 'SRG-OS-000471-GPOS-00216', 'SRG-OS-000472-GPOS-00217', 'SRG-OS-000473-GPOS-00218', 'SRG-OS-000474-GPOS-00219', 'SRG-OS-000475-GPOS-00220', 'SRG-OS-000476-GPOS-00221', 'SRG-OS-000477-GPOS-00222', 'SRG-OS-000755-GPOS-00220']
  tag 'documentable'
  tag cci: ['CCI-000130', 'CCI-000131', 'CCI-000132', 'CCI-000133', 'CCI-000134', 'CCI-000135', 'CCI-000159', 'CCI-001464', 'CCI-001487', 'CCI-001494', 'CCI-001495', 'CCI-001914', 'CCI-001889', 'CCI-001890', 'CCI-003938', 'CCI-002884', 'CCI-000172', 'CCI-004188']
  tag nist: ['AU-3 a', 'AU-3 b', 'AU-3 c', 'AU-3 d', 'AU-3 e', 'AU-3 (1)', 'AU-8 a', 'AU-14 (1)', 'AU-3 f', 'AU-9', 'AU-9', 'AU-12 (3)', 'AU-8 b', 'AU-8 b', 'CM-5 (1) (b)', 'MA-4 (1) (a)', 'AU-12 c', 'MA-3 (5)']

  describe macos_launchd_service('com.apple.auditd') do
    it { should be_loaded }
  end

  describe file('/etc/security/audit_control') do
    it { should exist }
  end

  describe command('/usr/sbin/audit -c') do
    its('stdout') { should include 'AUC_AUDITING' }
  end
end
