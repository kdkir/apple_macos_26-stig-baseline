control 'SV-277054' do
  title 'The macOS system must configure SSHD unused connection timeout to 900.'
  desc 'If SSHD is enabled, it must be configured with unused connection timeout set to 900.

This will set the timeout when there are no open channels within a session.

Note: /etc/ssh/sshd_config will be automatically modified to its original state following any update or major upgrade to the operating system.

'
  desc 'check', %q(Verify the macOS system is configured to set the SSHD unused connection timeout to 900 with the following command:

/usr/sbin/sshd -G | /usr/bin/awk '/unusedconnectiontimeout/{print $2}'

If the result is not "900", this is a finding.)
  desc 'fix', %q(Configure the macOS system to set the SSHD unused connection timeout to 900 with the following command:

include_dir=$(/usr/bin/awk '/^Include/ {print $2}' /etc/ssh/sshd_config | /usr/bin/tr -d '*')

if [[ -z $include_dir ]]; then
  /usr/bin/sed -i.bk "1s/.*/Include \/etc\/ssh\/sshd_config.d\/\*/" /etc/ssh/sshd_config
fi

/usr/bin/grep -qxF 'unusedconnectiontimeout 900' "${include_dir}01-mscp-sshd.conf" 2>/dev/null || echo "unusedconnectiontimeout 900" >> "${include_dir}01-mscp-sshd.conf"

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
  tag check_id: 'C-81209r1148612_chk'
  tag severity: 'medium'
  tag gid: 'V-277054'
  tag rid: 'SV-277054r1148614_rule'
  tag stig_id: 'APPL-26-000130'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag fix_id: 'F-81114r1148613_fix'
  tag satisfies: ['SRG-OS-000163-GPOS-00072', 'SRG-OS-000279-GPOS-00109']
  tag 'documentable'
  tag cci: ['CCI-001133', 'CCI-002361']
  tag nist: ['SC-10', 'AC-12']

  describe sshd_effective_config do
    its(['unusedconnectiontimeout']) { should cmp '900' }
  end
end
