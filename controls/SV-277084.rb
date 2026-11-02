control 'SV-277084' do
  title 'The macOS system must disable password authentication for SSH.'
  desc 'If remote login through SSH is enabled, password-based authentication must be disabled for user login.

All users must go through multifactor authentication to prevent unauthenticated access and potential compromise to the system.

Note: /etc/ssh/sshd_config will be automatically modified to its original state following any update or major upgrade to the operating system.

'
  desc 'check', %q(Verify the macOS system is configured to disable password authentication for SSH with the following command:

/usr/sbin/sshd -G | /usr/bin/grep -Ec '^(passwordauthentication\s+no|kbdinteractiveauthentication\s+no)'

If the result is not "2", this is a finding.)
  desc 'fix', %q(Configure the macOS system to disable password authentication for SSH with the following command:

include_dir=$(/usr/bin/awk '/^Include/ {print $2}' /etc/ssh/sshd_config | /usr/bin/tr -d '*')
if [[ -z $include_dir ]]; then
  /usr/bin/sed -i.bk "1s/.*/Include \/etc\/ssh\/sshd_config.d\/\*/" /etc/ssh/sshd_config
fi
echo "passwordauthentication no" >> "${include_dir}01-mscp-sshd.conf"
echo "kbdinteractiveauthentication no" >> "${include_dir}01-mscp-sshd.conf"

for file in $(ls ${include_dir}); do
  if [[ "$file" == "100-macos.conf" ]]; then
      continue
  fi
  if [[ "$file" == "01-mscp-sshd.conf" ]]; then
      break
  fi
  /bin/mv ${include_dir}${file} ${include_dir}20-${file}
done)
  impact 0.7
  tag check_id: 'C-81239r1148702_chk'
  tag severity: 'high'
  tag gid: 'V-277084'
  tag rid: 'SV-277084r1148704_rule'
  tag stig_id: 'APPL-26-001150'
  tag gtitle: 'SRG-OS-000067-GPOS-00035'
  tag fix_id: 'F-81144r1148703_fix'
  tag satisfies: ['SRG-OS-000067-GPOS-00035', 'SRG-OS-000105-GPOS-00052', 'SRG-OS-000106-GPOS-00053', 'SRG-OS-000107-GPOS-00054', 'SRG-OS-000108-GPOS-00055', 'SRG-OS-000112-GPOS-00057', 'SRG-OS-000125-GPOS-00065', 'SRG-OS-000375-GPOS-00160']
  tag 'documentable'
  tag cci: ['CCI-000186', 'CCI-000765', 'CCI-000766', 'CCI-001941', 'CCI-000877', 'CCI-004046']
  tag nist: ['IA-5 (2) (a) (1)', 'IA-2 (1)', 'IA-2 (2)', 'IA-2 (8)', 'MA-4 c', 'IA-2 (6) (a)']

  describe sshd_effective_config do
    its(['passwordauthentication']) { should cmp 'no' }
    its(['kbdinteractiveauthentication']) { should cmp 'no' }
  end
end
