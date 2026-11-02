control 'SV-277161' do
  title 'The macOS system must configure system log files owned by root and group to wheel.'
  desc 'The system log files must be owned by root.

System logs contain sensitive data about the system and users. Setting log files to be readable and writable only by system administrators mitigates the risk.

'
  desc 'check', %q(Verify the macOS system is configured with system log files owned by root and group to wheel with the following command:

/usr/bin/stat -f '%Su:%Sg:%N' $(/usr/bin/grep -v '^#' /etc/newsyslog.conf | /usr/bin/awk '{ print $1 }') 2> /dev/null | /usr/bin/awk '!/^root:wheel:/{print $1}' | /usr/bin/wc -l | /usr/bin/tr -d ' '

If the result is not "0", this is a finding.)
  desc 'fix', %q(Configure the macOS system with system log files owned by root and group to wheel with the following command: 

/usr/sbin/chown root:wheel $(/usr/bin/stat -f '%Su:%Sg:%N' $(/usr/bin/grep -v '^#' /etc/newsyslog.conf | /usr/bin/awk '{ print $1 }') 2> /dev/null | /usr/bin/awk -F":" '!/^root:wheel:/{print $3}'))
  impact 0.5
  tag check_id: 'C-81316r1148933_chk'
  tag severity: 'medium'
  tag gid: 'V-277161'
  tag rid: 'SV-277161r1148935_rule'
  tag stig_id: 'APPL-26-004030'
  tag gtitle: 'SRG-OS-000205-GPOS-00083'
  tag fix_id: 'F-81221r1148934_fix'
  tag satisfies: ['SRG-OS-000205-GPOS-00083', 'SRG-OS-000206-GPOS-00084']
  tag 'documentable'
  tag cci: ['CCI-001312', 'CCI-001314']
  tag nist: ['SI-11 a', 'SI-11 b']
end
