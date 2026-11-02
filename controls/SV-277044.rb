control 'SV-277044' do
  title 'The macOS system must configure SSHD ClientAliveCountMax to 1.'
  desc 'If SSHD is enabled, it must be configured with the Client Alive Maximum Count set to 1.

This will set the number of client alive messages that may be sent without the SSH server receiving any messages back from the client. If this threshold is reached while client alive messages are being sent, the SSH server will disconnect the client, terminating the session. The client alive messages are sent through the encrypted channel and therefore, cannot be spoofed. The client alive mechanism is valuable when the client or server depends on knowing when a connection has become unresponsive.

Note: This setting is not intended to manage idle user sessions where there is no input from the client. Its purpose is to look for interruptions in network connectivity and force the session to terminate after the connection appears to be broken.

Note: /etc/ssh/sshd_config will be automatically modified to its original state following any update or major upgrade to the operating system.'
  desc 'check', %q(Verify the macOS system is configured to set the SSHD ClientAliveCountMax to 1 with the following command:

/usr/sbin/sshd -G | /usr/bin/awk '/clientalivecountmax/{print $2}'

If the result is not "1", this is a finding.)
  desc 'fix', %q(Configure the macOS system to set the SSHD ClientAliveCountMax to 1 with the following command:

include_dir=$(/usr/bin/awk '/^Include/ {print $2}' /etc/ssh/sshd_config | /usr/bin/tr -d '*')

if [[ -z $include_dir ]]; then
  /usr/bin/sed -i.bk "1s/.*/Include \/etc\/ssh\/sshd_config.d\/\*/" /etc/ssh/sshd_config
fi

/usr/bin/grep -qxF 'clientalivecountmax 1' "${include_dir}01-mscp-sshd.conf" 2>/dev/null || echo "clientalivecountmax 1" >> "${include_dir}01-mscp-sshd.conf"

for file in $(ls ${include_dir}); do
  if [[ "$file" == "100-macos.conf" ]]; then
      continue
  fi
  if [[ "$file" == "01-mscp-sshd.conf" ]]; then
      break
  fi
  /bin/mv ${include_dir}${file} ${include_dir}20-${file}
done)
  impact 0.5
  tag check_id: 'C-81199r1148582_chk'
  tag severity: 'medium'
  tag gid: 'V-277044'
  tag rid: 'SV-277044r1149437_rule'
  tag stig_id: 'APPL-26-000052'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag fix_id: 'F-81104r1148583_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']

  describe sshd_effective_config do
    its(['clientalivecountmax']) { should cmp '1' }
  end
end
