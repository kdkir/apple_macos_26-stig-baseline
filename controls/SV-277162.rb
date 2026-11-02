control 'SV-277162' do
  title 'The macOS system must configure system log files to mode 640 or less permissive.'
  desc 'The system logs must be configured to be writable by root and readable only by the root user and group wheel. To achieve this, system log files must be configured to mode 640 permissive or less, thereby preventing normal users from reading, modifying, or deleting audit logs. 

System logs frequently contain sensitive information that could be used by an attacker. Setting the correct permissions mitigates this risk.

'
  desc 'check', %q(Verify the macOS system is configured with system log files set to mode 640 or less permissive with the following command:

/usr/bin/stat -f '%A:%N' $(/usr/bin/grep -v '^#' /etc/newsyslog.conf | /usr/bin/awk '{ print $1 }') 2> /dev/null | /usr/bin/awk '!/640/{print $1}' | /usr/bin/wc -l | /usr/bin/tr -d ' '

If the result is not "0", this is a finding.)
  desc 'fix', %q(Configure the macOS system with system log files set to mode 640 or less permissive with the following command:

/bin/chmod 640 $(/usr/bin/stat -f '%A:%N' $(/usr/bin/grep -v '^#' /etc/newsyslog.conf | /usr/bin/awk '{ print $1 }') 2> /dev/null | /usr/bin/awk '!/640/{print $1}' | awk -F":" '!/640/{print $2}'))
  impact 0.5
  tag check_id: 'C-81317r1148936_chk'
  tag severity: 'medium'
  tag gid: 'V-277162'
  tag rid: 'SV-277162r1148938_rule'
  tag stig_id: 'APPL-26-004040'
  tag gtitle: 'SRG-OS-000205-GPOS-00083'
  tag fix_id: 'F-81222r1148937_fix'
  tag satisfies: ['SRG-OS-000205-GPOS-00083', 'SRG-OS-000206-GPOS-00084']
  tag 'documentable'
  tag cci: ['CCI-001312', 'CCI-001314']
  tag nist: ['SI-11 a', 'SI-11 b']
end
