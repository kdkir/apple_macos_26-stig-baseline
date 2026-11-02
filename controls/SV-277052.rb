control 'SV-277052' do
  title 'The macOS system must configure the SSH ServerAliveInterval to 900.'
  desc 'SSH must be configured with an Active Server Alive Maximum Count set to 900.

Setting the Active Server Alive Maximum Count to 900 will log users out after a 900-second interval of inactivity.

Note: /etc/ssh/ssh_config will be automatically modified to its original state following any update or major upgrade to the operating system.'
  desc 'check', %q(Verify the macOS system is configured to set the SSH ServerAliveInterval to 900 with the following command:

ret="pass"
for u in $(/usr/bin/dscl . -list /Users UniqueID | /usr/bin/awk '$2 > 500 {print $1}'); do
sshCheck=$(/usr/bin/sudo -u $u /usr/bin/ssh -G . | /usr/bin/grep -c "^serveraliveinterval 900")
if [[ "$sshCheck" == "0" ]]; then
ret="fail"
break
fi
done
/bin/echo $ret

If the result is not "pass", this is a finding.)
  desc 'fix', %q(Configure the macOS system to set the SSH ServerAliveInterval to 900 with the following command:

include_dir=$(/usr/bin/awk '/^Include/ {print $2}' /etc/ssh/ssh_config | /usr/bin/tr -d '*')
  
ssh_config_string=("ServerAliveInterval 900")
for ssh_config in $ssh_config_string; do
ssh_setting=$(echo $ssh_config | /usr/bin/cut -d " " -f1)
/usr/bin/grep -qEi "^$ssh_setting" "${include_dir}01-mscp-ssh.conf" && /usr/bin/sed -i "" "s/^$ssh_setting.*/${ssh_config}/" "${include_dir}01-mscp-ssh.conf" || echo "$ssh_config" >> "${include_dir}01-mscp-ssh.conf"
for u in $(/usr/bin/dscl . list /users shell | /usr/bin/egrep -v '(^_)|(root)|(/usr/bin/false)' | /usr/bin/awk '{print $1}'); do
config=$(/usr/bin/sudo -u $u /usr/bin/ssh -Gv . 2>&1)
configfiles=$(echo "$config" | /usr/bin/awk '/Reading configuration data/ {print $NF}'| /usr/bin/tr -d '\r')
configarray=( ${(f)configfiles} )
if ! echo $config | /usr/bin/grep -q -i "$ssh_config" ; then
for c in $configarray; do
if [[ "$c" == "/etc/ssh/crypto.conf" ]]; then
continue
fi
          
/usr/bin/sudo -u $u /usr/bin/grep -qEi "^$ssh_setting" "$c" && /usr/bin/sed -i "" "s/^$ssh_setting.*/${ssh_config}/I" "$c"
if [[ "$c" =~ ".ssh/config" ]]; then
if /usr/bin/grep -qEi "$ssh_setting" "$c" 2> /dev/null; then
old_file=$(cat ~$u/.ssh/config)
echo "$ssh_config" > ~$u/.ssh/config
echo "$old_file" >> ~$u/.ssh/config
fi
fi
done
fi
done
done)
  impact 0.5
  tag check_id: 'C-81207r1148606_chk'
  tag severity: 'medium'
  tag gid: 'V-277052'
  tag rid: 'SV-277052r1148608_rule'
  tag stig_id: 'APPL-26-000110'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag fix_id: 'F-81112r1148607_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
