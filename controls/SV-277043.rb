control 'SV-277043' do
  title 'The macOS system must configure SSHD ClientAliveInterval to 900.'
  desc 'If SSHD is enabled, it must be configured with the Client Alive Interval set to 900.

This sets a timeout interval in seconds, after which if no data has been received from the client, sshd(8) will send a message through the encrypted channel to request a response from the client.

This setting works in conjunction with ClientAliveCountMax to determine the termination of the connection after the threshold has been reached.

Note: This setting is not intended to manage idle user sessions where there is no input from the client. Its purpose is to look for interruptions in network connectivity and force the session to terminate after the connection appears to be broken.

Note: /etc/ssh/sshd_config will be automatically modified to its original state following any update or major upgrade to the operating system.'
  desc 'check', %q(Verify the macOS system is configured to set the SSHD ClientAliveInterval to 900 with the following command:

/usr/sbin/sshd -G | /usr/bin/awk '/clientaliveinterval/{print $2}'

If the result is not "900", this is a finding.)
  desc 'fix', %q(Configure the macOS system to set the SSHD ClientAliveInterval to 900 with the following command:

include_dir=$(/usr/bin/awk '/^Include/ {print $2}' /etc/ssh/sshd_config | /usr/bin/tr -d '*')

if [[ -z $include_dir ]]; then
/usr/bin/sed -i.bk "1s/.*/Include \/etc\/ssh\/sshd_config.d\/\*/" /etc/ssh/sshd_config
fi

/usr/bin/grep -qxF 'clientaliveinterval 900' "${include_dir}01-mscp-sshd.conf" 2>/dev/null || echo "clientaliveinterval 900" >> "${include_dir}01-mscp-sshd.conf"

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
  tag check_id: 'C-81198r1148579_chk'
  tag severity: 'medium'
  tag gid: 'V-277043'
  tag rid: 'SV-277043r1148581_rule'
  tag stig_id: 'APPL-26-000051'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag fix_id: 'F-81103r1148580_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']

  describe sshd_effective_config do
    its(['clientaliveinterval']) { should cmp '900' }
  end
end
