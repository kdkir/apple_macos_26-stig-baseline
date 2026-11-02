control 'SV-277078' do
  title 'The macOS system must set smart card certificate trust to moderate.'
  desc 'The macOS system must be configured to block access to users who are no longer authorized (i.e., users with revoked certificates).

To prevent the use of untrusted certificates, the certificates on a smart card must meet the following criteria: its issuer has a system-trusted certificate, the certificate is not expired, its "valid-after" date is in the past, and it passes Certificate Revocation List (CRL) and Online Certificate Status Protocol (OCSP) checking.

By setting the smart card certificate trust level to moderate, the system will execute a soft revocation, meaning, if the OCSP/CRL server is unreachable, authentication will still succeed.

Note: Before applying this setting, refer to the smart card supplemental guidance.

'
  desc 'check', %q(Verify the macOS system is configured to check the revocation status of user certificates with the following command:

/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.security.smartcard')\
.objectForKey('checkCertificateTrust').js
EOS

If the result is not "2", this is a finding.)
  desc 'fix', 'Configure the macOS system to check the revocation status of user certificates by installing the "com.apple.security.smartcard" configuration profile. 

Note: To ensure continued access to the operating system, consult the supplemental guidance provided with the STIG before applying the configuration profile.'
  impact 0.5
  tag check_id: 'C-81233r1148684_chk'
  tag severity: 'medium'
  tag gid: 'V-277078'
  tag rid: 'SV-277078r1148686_rule'
  tag stig_id: 'APPL-26-001060'
  tag gtitle: 'SRG-OS-000066-GPOS-00034'
  tag fix_id: 'F-81138r1148685_fix'
  tag satisfies: ['SRG-OS-000066-GPOS-00034', 'SRG-OS-000377-GPOS-00162', 'SRG-OS-000384-GPOS-00167', 'SRG-OS-000403-GPOS-00182']
  tag 'documentable'
  tag cci: ['CCI-000185', 'CCI-001954', 'CCI-004068', 'CCI-002470']
  tag nist: ['IA-5 (2) (b) (1)', 'IA-2 (12)', 'IA-5 (2) (b) (2)', 'SC-23 (5)']

  describe macos_managed_preference('com.apple.security.smartcard', 'checkCertificateTrust') do
    its('value') { should eq 2 }
  end
end
