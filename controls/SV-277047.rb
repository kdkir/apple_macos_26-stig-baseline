control 'SV-277047' do
  title 'The macOS system must limit SSH to FIPS-compliant connections.'
  desc 'SSH must be configured to limit the Ciphers, HostbasedAcceptedAlgorithms, HostKeyAlgorithms, KexAlgorithms, MACs, PubkeyAcceptedAlgorithms, CASignatureAlgorithms to algorithms that are FIPS-140 validated.

FIPS 140-3 is the current standard for validating that mechanisms used to access cryptographic modules use authentication that meets federal requirements.

Operating systems using encryption must use FIPS-validated mechanisms for authenticating to cryptographic modules.

Note: For more information on FIPS compliance with the version of SSH included in the macOS, the manual page apple_ssh_and_fips has additional information.

'
  desc 'check', %q(Verify the macOS system is configured to limit SSH to FIPS-compliant connections with the following command:

fips_ssh_config=("Ciphers aes128-gcm@openssh.com" "HostbasedAcceptedAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com" "HostKeyAlgorithms ecdsa-sha2-nistp256-cert-v01@openssh.com,sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp256,sk-ecdsa-sha2-nistp256@openssh.com" "KexAlgorithms ecdh-sha2-nistp256" "MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-256" "PubkeyAcceptedAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com,sk-ecdsa-sha2-nistp256-cert-v01@openssh.com" "CASignatureAlgorithms ecdsa-sha2-nistp256,sk-ecdsa-sha2-nistp256@openssh.com")
total=0
ret="pass"
for config in $fips_ssh_config; do
if [[ "$ret" == "fail" ]]; then
break
fi
for u in $(/usr/bin/dscl . list /users shell | /usr/bin/egrep -v '(^_)|(root)|(/usr/bin/false)' | /usr/bin/awk '{print $1}'); do
sshCheck=$(/usr/bin/sudo -u $u /usr/bin/ssh -G . | /usr/bin/grep -ci "$config")
if [[ "$sshCheck" == "0" ]]; then
ret="fail"
break
fi
done
done
echo $ret

If the result is not "pass", this is a finding.)
  desc 'fix', %q(Configure the macOS system to limit SSH to FIPS-compliant connections with the following command:

if [ -f /etc/ssh/crypto.conf ] && /usr/bin/grep -q "Include /etc/ssh/crypto.conf" /etc/ssh/ssh_config.d/100-macos.conf 2>/dev/null; then
/bin/ln -fs /etc/ssh/crypto/fips.conf /etc/ssh/crypto.conf
fi
include_dir=$(/usr/bin/awk '/^Include/ {print $2}' /etc/ssh/ssh_config | /usr/bin/tr -d '*')

fips_ssh_config=("Ciphers aes128-gcm@openssh.com" "HostbasedAcceptedAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com" "HostKeyAlgorithms ecdsa-sha2-nistp256-cert-v01@openssh.com,sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp256,sk-ecdsa-sha2-nistp256@openssh.com" "KexAlgorithms ecdh-sha2-nistp256" "MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-256" "PubkeyAcceptedAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com,sk-ecdsa-sha2-nistp256-cert-v01@openssh.com" "CASignatureAlgorithms ecdsa-sha2-nistp256,sk-ecdsa-sha2-nistp256@openssh.com")
for ssh_config in $fips_ssh_config; do
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
  impact 0.7
  tag check_id: 'C-81202r1148591_chk'
  tag severity: 'high'
  tag gid: 'V-277047'
  tag rid: 'SV-277047r1268222_rule'
  tag stig_id: 'APPL-26-000057'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag fix_id: 'F-81107r1148592_fix'
  tag satisfies: ['SRG-OS-000033-GPOS-00014', 'SRG-OS-000120-GPOS-00061', 'SRG-OS-000250-GPOS-00093', 'SRG-OS-000396-GPOS-00176', 'SRG-OS-000424-GPOS-00188', 'SRG-OS-000478-GPOS-00223']
  tag 'documentable'
  tag cci: ['CCI-000068', 'CCI-000803', 'CCI-001453', 'CCI-002450', 'CCI-002421']
  tag nist: ['AC-17 (2)', 'IA-7', 'AC-17 (2)', 'SC-13 b', 'SC-8 (1)']

  users = macos_local_users.interactive

  if users.empty?
    describe 'Local interactive user accounts' do
      skip 'No local interactive user accounts were found to evaluate.'
    end
  else
    users.each do |user|
      describe ssh_effective_config(user) do
        MacosSshEffectiveConfigParser::FIPS_ALGORITHMS.each do |keyword, value|
          its([keyword]) { should cmp value }
        end
      end
    end
  end
end
