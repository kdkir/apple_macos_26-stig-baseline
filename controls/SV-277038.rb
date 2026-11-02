control 'SV-277038' do
  title 'The macOS system must enforce SSH to display a policy banner.'
  desc 'SSH must be configured to display a policy banner.

Displaying a standardized and approved use notification before granting access to the operating system ensures that users are provided with privacy and security notification verbiage that is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

System use notifications are required only for access via login interfaces with human users and are not required when such human interfaces do not exist.

Note: /etc/ssh/sshd_config will be automatically modified to its original state following any update or major upgrade to the operating system.

'
  desc 'check', 'Verify the macOS system is configured to display the contents of "/etc/banner" before granting access to the system with the following command:

/usr/sbin/sshd -G | /usr/bin/grep -c "^banner /etc/banner"

If the command does not return "1", this is a finding.'
  desc 'fix', %q(Configure the macOS system to display the contents of "/etc/banner" before granting access to the system with the following command:

include_dir=$(/usr/bin/awk '/^Include/ {print $2}' /etc/ssh/sshd_config | /usr/bin/tr -d '*')

if [[ -z $include_dir ]]; then
/usr/bin/sed -i.bk "1s/.*/Include \/etc\/ssh\/sshd_config.d\/\*/" /etc/ssh/sshd_config
fi

/usr/bin/grep -qxF 'banner /etc/banner' "${include_dir}01-mscp-sshd.conf" 2>/dev/null || echo "banner /etc/banner" >> "${include_dir}01-mscp-sshd.conf"

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
  tag check_id: 'C-81193r1148564_chk'
  tag severity: 'medium'
  tag gid: 'V-277038'
  tag rid: 'SV-277038r1268215_rule'
  tag stig_id: 'APPL-26-000024'
  tag gtitle: 'SRG-OS-000023-GPOS-00006'
  tag fix_id: 'F-81098r1148565_fix'
  tag satisfies: ['SRG-OS-000023-GPOS-00006', 'SRG-OS-000024-GPOS-00007']
  tag 'documentable'
  tag cci: ['CCI-000048', 'CCI-000050']
  tag nist: ['AC-8 a', 'AC-8 b']
end
