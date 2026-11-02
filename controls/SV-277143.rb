control 'SV-277143' do
  title 'The macOS system must issue or obtain public key certificates from an approved service provider.'
  desc 'The organization must issue or obtain public key certificates from an organization-approved service provider and ensure only approved trust anchors are in the System Keychain.

'
  desc 'check', %q(Verify the macOS system is configured to issue or obtain public key certificates from an approved service provider with the following command:

/usr/bin/security dump-keychain /Library/Keychains/System.keychain | /usr/bin/awk -F'"' '/labl/ {print $4}'

If the result does not contain a list of approved certificate authorities, this is a finding.)
  desc 'fix', 'Configure the macOS system to issue or obtain public key certificates from an approved service provider by obtaining the approved certificates from the appropriate authority and install them to the System Keychain.'
  impact 0.5
  tag check_id: 'C-81298r1148879_chk'
  tag severity: 'medium'
  tag gid: 'V-277143'
  tag rid: 'SV-277143r1268247_rule'
  tag stig_id: 'APPL-26-003001'
  tag gtitle: 'SRG-OS-000403-GPOS-00182'
  tag fix_id: 'F-81203r1148880_fix'
  tag satisfies: ['SRG-OS-000403-GPOS-00182', 'SRG-OS-000775-GPOS-00230']
  tag 'documentable'
  tag cci: ['CCI-002470', 'CCI-004909']
  tag nist: ['SC-23 (5)', 'SC-17 b']
end
