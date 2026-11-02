control 'SV-277059' do
  title 'The macOS system must configure sudo to log events.'
  desc 'Sudo must be configured to log privilege escalation.

Without logging privilege escalation, it is difficult to identify attempted attacks because no audit trail is available for forensic investigation.'
  desc 'check', 'Verify the macOS system is configured to log privilege escalation with the following command:

/usr/bin/sudo /usr/bin/sudo -V | /usr/bin/grep -c "Log when a command is allowed by sudoers"

If the result is not "1", this is a finding.'
  desc 'fix', %q(Configure the macOS system to log privilege escalation with the following command:

/usr/bin/find /etc/sudoers* -type f -exec sed -i '' '/^Defaults[[:blank:]]*\!log_allowed/s/^/# /' '{}' \;
/bin/echo "Defaults log_allowed" >> /etc/sudoers.d/mscp)
  impact 0.5
  tag check_id: 'C-81214r1148627_chk'
  tag severity: 'medium'
  tag gid: 'V-277059'
  tag rid: 'SV-277059r1148629_rule'
  tag stig_id: 'APPL-26-000190'
  tag gtitle: 'SRG-OS-000064-GPOS-00033'
  tag fix_id: 'F-81119r1148628_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  describe command('/usr/bin/sudo -V') do
    its('stdout') { should include 'Log when a command is allowed by sudoers' }
  end
end
