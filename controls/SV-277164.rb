control 'SV-277164' do
  title 'The macOS system must configure sudoers timestamp type.'
  desc %q(The file /etc/sudoers must be configured to not include a timestamp_type of global or ppid and be configured for timestamp record types of tty.

This rule ensures that the "sudo" command will prompt for the administrator's password at least once in each newly opened terminal window. This prevents a malicious user from taking advantage of an unlocked computer or an abandoned logon session by bypassing the normal password prompt requirement.

)
  desc 'check', %q(Verify the macOS system is configured with sudoers timestamp type with the following command:

/usr/bin/sudo /usr/bin/sudo -V | /usr/bin/awk -F": " '/Type of authentication timestamp record/{print $2}'

If the result is not "tty", this is a finding.)
  desc 'fix', "Configure the macOS system with sudoers timestamp type with the following command:

/usr/bin/find /etc/sudoers* -type f -exec sed -i '' '/timestamp_type/d; /!tty_tickets/d' '{}' \\;"
  impact 0.5
  tag check_id: 'C-81319r1148942_chk'
  tag severity: 'medium'
  tag gid: 'V-277164'
  tag rid: 'SV-277164r1148944_rule'
  tag stig_id: 'APPL-26-004060'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag fix_id: 'F-81224r1148943_fix'
  tag satisfies: ['SRG-OS-000373-GPOS-00156', 'SRG-OS-000373-GPOS-00157']
  tag 'documentable'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
