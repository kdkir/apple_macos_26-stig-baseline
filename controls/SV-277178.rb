control 'SV-277178' do
  title 'The macOS system must ensure Secure Boot level is set to "full".'
  desc 'The Secure Boot security setting must be set to "full".

Full security is the default Secure Boot setting in macOS. During startup, when Secure Boot is set to full security, the Mac will verify the integrity of the operating system before allowing the operating system to boot.

Note: This will only return a proper result on a T2 or Apple Silicon Macs.

'
  desc 'check', 'Verify the macOS system is configured to ensure Secure Boot level is set to "full" using the following command:

/usr/libexec/mdmclient QuerySecurityInfo 2>/dev/null | /usr/bin/grep -c "SecureBootLevel = full"

If the result is not "1", this is a finding.'
  desc 'fix', 'Configure the macOS system to ensure Secure Boot level is set to "full" by booting into Recovery Mode and enabling Full Secure Boot.'
  impact 0.5
  tag check_id: 'C-81333r1149335_chk'
  tag severity: 'medium'
  tag gid: 'V-277178'
  tag rid: 'SV-277178r1149395_rule'
  tag stig_id: 'APPL-26-005100'
  tag gtitle: 'SRG-OS-000445-GPOS-00199'
  tag fix_id: 'F-81238r1148985_fix'
  tag satisfies: ['SRG-OS-000445-GPOS-00199', 'SRG-OS-000446-GPOS-00200', 'SRG-OS-000447-GPOS-00201']
  tag 'documentable'
  tag cci: ['CCI-002696', 'CCI-002699', 'CCI-002702']
  tag nist: ['SI-6 a', 'SI-6 b', 'SI-6 d']
end
