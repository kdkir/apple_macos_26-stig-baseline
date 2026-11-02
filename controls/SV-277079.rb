control 'SV-277079' do
  title 'The macOS system must disable root login for SSH.'
  desc 'If SSH is enabled to ensure individual accountability and prevent unauthorized access, logging in as root via SSH must be disabled.

The macOS system MUST require individuals to be authenticated with an individual authenticator prior to using a group authenticator, and administrator users must never log in directly as root.

Note: /etc/ssh/sshd_config will be automatically modified to its original state following any update or major upgrade to the operating system.

'
  desc 'check', %q(Verify the macOS system is configured to disable root login for SSH with the following command:

/usr/sbin/sshd -G | /usr/bin/awk '/permitrootlogin/{print $2}'

If the result is not "no", this is a finding.)
  desc 'fix', %q(Configure the macOS system to disable root login for SSH with the following command:

include_dir=$(/usr/bin/awk '/^Include/ {print $2}' /etc/ssh/sshd_config | /usr/bin/tr -d '*')

if [[ -z $include_dir ]]; then
  /usr/bin/sed -i.bk "1s/.*/Include \/etc\/ssh\/sshd_config.d\/\*/" /etc/ssh/sshd_config
fi

/usr/bin/grep -qxF 'permitrootlogin no' "${include_dir}01-mscp-sshd.conf" 2>/dev/null || echo "permitrootlogin no" >> "${include_dir}01-mscp-sshd.conf"

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
  tag check_id: 'C-81234r1148687_chk'
  tag severity: 'medium'
  tag gid: 'V-277079'
  tag rid: 'SV-277079r1148689_rule'
  tag stig_id: 'APPL-26-001100'
  tag gtitle: 'SRG-OS-000109-GPOS-00056'
  tag fix_id: 'F-81139r1148688_fix'
  tag satisfies: ['SRG-OS-000109-GPOS-00056', 'SRG-OS-000364-GPOS-00151']
  tag 'documentable'
  tag cci: ['CCI-004045', 'CCI-001813']
  tag nist: ['IA-2 (5)', 'CM-5 (1) (a)']

  describe sshd_effective_config do
    its(['permitrootlogin']) { should cmp 'no' }
  end
end
