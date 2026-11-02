control 'SV-277045' do
  title 'The macOS system must set login grace time to 30.'
  desc 'If SSHD is enabled, it must be configured to wait only 30 seconds before timing out login attempts.

Note: /etc/ssh/sshd_config will be automatically modified to its original state following any update or major upgrade to the operating system.'
  desc 'check', %q(Verify the macOS system is configured to set Login Grace Time to 30 with the following command:

/usr/sbin/sshd -G | /usr/bin/awk '/logingracetime/{print $2}'

If the result is not "30", this is a finding.)
  desc 'fix', %q(Configure the macOS system to set Login Grace Time to 30 with the following command:

include_dir=$(/usr/bin/awk '/^Include/ {print $2}' /etc/ssh/sshd_config | /usr/bin/tr -d '*')

if [[ -z $include_dir ]]; then
  /usr/bin/sed -i.bk "1s/.*/Include \/etc\/ssh\/sshd_config.d\/\*/" /etc/ssh/sshd_config
fi

/usr/bin/grep -qxF 'logingracetime 30' "${include_dir}01-mscp-sshd.conf" 2>/dev/null || echo "logingracetime 30" >> "${include_dir}01-mscp-sshd.conf"

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
  tag check_id: 'C-81200r1148585_chk'
  tag severity: 'medium'
  tag gid: 'V-277045'
  tag rid: 'SV-277045r1148587_rule'
  tag stig_id: 'APPL-26-000053'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag fix_id: 'F-81105r1148586_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
