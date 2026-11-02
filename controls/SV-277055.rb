control 'SV-277055' do
  title 'The macOS system must set SSH Active Server Alive Maximum to 0.'
  desc 'SSH must be configured with an Active Server Alive Maximum Count set to 0. Terminating an idle session within a short time reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. Quickly terminating an idle session or an incomplete login attempt will also free up resources committed by the managed network element.

Note: /etc/ssh/ssh_config will be automatically modified to its original state following any update or major upgrade to the operating system.'
  desc 'check', %q(Verify the macOS system is configured to set SSH Active Server Alive Maximum to 0 with the following command:

ret="pass"
for u in $(/usr/bin/dscl . -list /Users UniqueID | /usr/bin/awk '$2 > 500 {print $1}'); do
sshCheck=$(/usr/bin/sudo -u $u /usr/bin/ssh -G . | /usr/bin/grep -c "^serveralivecountmax 0")
if [[ "$sshCheck" == "0" ]]; then
ret="fail"
break
fi
done
/bin/echo $ret

If the result is not "pass", this is a finding.)
  desc 'fix', %q(Configure the macOS system to set SSH Active Server Alive Maximum to 0 with the following command:

include_dir=$(/usr/bin/awk '/^Include/ {print $2}' /etc/ssh/ssh_config | /usr/bin/tr -d '*')
  
ssh_config=("ServerAliveCountMax 0")
  
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
done)
  impact 0.5
  tag check_id: 'C-81210r1148615_chk'
  tag severity: 'medium'
  tag gid: 'V-277055'
  tag rid: 'SV-277055r1148617_rule'
  tag stig_id: 'APPL-26-000140'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag fix_id: 'F-81115r1148616_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
