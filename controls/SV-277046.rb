control 'SV-277046' do
  title 'The macOS system must limit SSHD to FIPS-compliant connections.'
  desc 'If SSHD is enabled, it must be configured to limit the Ciphers, HostbasedAcceptedAlgorithms, HostKeyAlgorithms, KexAlgorithms, MACs, PubkeyAcceptedAlgorithms, CASignatureAlgorithms to algorithms that are FIPS-140 validated.

FIPS 140-2/140-3 is the current standard for validating that mechanisms used to access cryptographic modules use authentication that meets federal requirements.

Operating systems using encryption must use FIPS-validated mechanisms for authenticating to cryptographic modules.

Note: For more information on FIPS compliance with the version of SSHD included in the macOS, the manual page apple_ssh_and_fips has additional information.

'
  desc 'check', 'Verify the macOS system is configured to limit SSHD to FIPS-compliant connections with the following command:

fips_sshd_config=("Ciphers aes128-gcm@openssh.com" "HostbasedAcceptedAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com" "HostKeyAlgorithms ecdsa-sha2-nistp256-cert-v01@openssh.com,sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp256,sk-ecdsa-sha2-nistp256@openssh.com" "KexAlgorithms ecdh-sha2-nistp256" "MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-256" "PubkeyAcceptedAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com,sk-ecdsa-sha2-nistp256-cert-v01@openssh.com" "CASignatureAlgorithms ecdsa-sha2-nistp256,sk-ecdsa-sha2-nistp256@openssh.com")
total=0
for config in $fips_sshd_config; do
total=$(expr $(/usr/sbin/sshd -G | /usr/bin/grep -i -c "$config") + $total)
done

echo $total

If the result is not "7", this is a finding.'
  desc 'fix', %q(Configure the macOS system to limit SSHD to FIPS-compliant connections with the following command:

if [ -f /etc/ssh/crypto.conf ] && /usr/bin/grep -q "Include /etc/ssh/crypto.conf" /etc/ssh/sshd_config.d/100-macos.conf 2>/dev/null; then
/bin/ln -fs /etc/ssh/crypto/fips.conf /etc/ssh/crypto.conf
fi

include_dir=$(/usr/bin/awk '/^Include/ {print $2}' /etc/ssh/sshd_config | /usr/bin/tr -d '*')

if [[ -z $include_dir ]]; then
/usr/bin/sed -i.bk "1s/.*/Include \/etc\/ssh\/sshd_config.d\/\*/" /etc/ssh/sshd_config
fi

fips_sshd_config=("Ciphers aes128-gcm@openssh.com" "HostbasedAcceptedAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com" "HostKeyAlgorithms ecdsa-sha2-nistp256-cert-v01@openssh.com,sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp256,sk-ecdsa-sha2-nistp256@openssh.com" "KexAlgorithms ecdh-sha2-nistp256" "MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-256" "PubkeyAcceptedAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com,sk-ecdsa-sha2-nistp256-cert-v01@openssh.com" "CASignatureAlgorithms ecdsa-sha2-nistp256,sk-ecdsa-sha2-nistp256@openssh.com")
sshd_config=$(/usr/sbin/sshd -G)
for config in $fips_sshd_config; do
if ! echo $sshd_config | /usr/bin/grep -q -i "$config" 2>/dev/null; then
/usr/bin/grep -qxF "$config" "${include_dir}01-mscp-sshd.conf" 2>/dev/null || echo "$config" >> "${include_dir}01-mscp-sshd.conf"
fi
done

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
  tag check_id: 'C-81201r1148588_chk'
  tag severity: 'high'
  tag gid: 'V-277046'
  tag rid: 'SV-277046r1268222_rule'
  tag stig_id: 'APPL-26-000054'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag fix_id: 'F-81106r1184567_fix'
  tag satisfies: ['SRG-OS-000033-GPOS-00014', 'SRG-OS-000120-GPOS-00061', 'SRG-OS-000250-GPOS-00093', 'SRG-OS-000393-GPOS-00173', 'SRG-OS-000394-GPOS-00174', 'SRG-OS-000396-GPOS-00176', 'SRG-OS-000424-GPOS-00188', 'SRG-OS-000478-GPOS-00223']
  tag 'documentable'
  tag cci: ['CCI-000068', 'CCI-000803', 'CCI-001453', 'CCI-002890', 'CCI-003123', 'CCI-002450', 'CCI-002421']
  tag nist: ['AC-17 (2)', 'IA-7', 'AC-17 (2)', 'MA-4 (6)', 'MA-4 (6)', 'SC-13 b', 'SC-8 (1)']

  sshd = sshd_effective_config

  describe sshd do
    sshd.fips_algorithms.each do |keyword, value|
      its([keyword]) { should cmp value }
    end
  end
end
