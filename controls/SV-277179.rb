control 'SV-277179' do
  title 'The macOS system must enforce enrollment in Mobile Device Management (MDM).'
  desc 'Users must enroll their Mac in MDM software.

User Approved MDM (UAMDM) enrollment or enrollment via Apple Business Manager (ABM)/Apple School Manager (ASM) is required to manage certain security settings. Currently, these include:

* Allowed Kernel Extensions.
* Allowed Approved System Extensions.
* Privacy Preferences Policy Control Payload.
* ExtensibleSingleSignOn.
* FDEFileVault.
* Activation Lock Bypass.
* Access to Bootstrap Tokens.
* Scheduling Software Updates.
* Query list and delete local users.'
  desc 'check', %q(Verify the macOS system is configured to enforce enrollment in mobile device management with the following command:

/usr/bin/profiles status -type enrollment | /usr/bin/awk -F: '/MDM enrollment/ {print $2}' | /usr/bin/grep -c "Yes (User Approved)"

If the result is not "1", this is a finding.)
  desc 'fix', 'Configure the macOS system by ensuring that the system is enrolled via UAMDM.'
  impact 0.5
  tag check_id: 'C-81334r1148987_chk'
  tag severity: 'medium'
  tag gid: 'V-277179'
  tag rid: 'SV-277179r1268251_rule'
  tag stig_id: 'APPL-26-005110'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-81239r1148988_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
